// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared proxy routing logic used by both SOCKS5 and HTTP proxy modules.
//!
//! After protocol-specific handshake, both produce a target `host:port` and a `TcpStream`.
//! This module handles the downstream routing: split tunnel decision → bypass/tunnel/block.

use std::time::Duration;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use rvpn_core::crypto::{IdentityKey, X3DHPublicBundle};

use crate::config::{ServerIdentityConfig, Socks5Mode};
use crate::router::Router;
use crate::server_pool::ServerPool;
use crate::socks5_tunnel::{self, Socks5Tunnel};
use crate::split_tunnel::{SplitTunnel, RoutingDecision};
use crate::stream_relay::StreamRelay;
use crate::tunnel_pool::TunnelPools;
use rvpn_tls::TlsFingerprint;

pub struct RunningMode {
    mode: Socks5Mode,
    pools: Option<Arc<TunnelPools>>,
}

#[derive(Default)]
struct Listeners {
    http: std::sync::Weak<RunningMode>,
    socks5: std::sync::Weak<RunningMode>,
}

static LISTENERS: std::sync::LazyLock<std::sync::Mutex<Listeners>> =
    std::sync::LazyLock::new(Default::default);

pub fn register_listener(protocol: ProxyProtocol, mode: Socks5Mode, pools: Option<Arc<TunnelPools>>) -> Arc<RunningMode> {
    let listener = Arc::new(RunningMode { mode, pools });
    let mut listeners = LISTENERS.lock().unwrap_or_else(|e| e.into_inner());
    match protocol {
        ProxyProtocol::Http => listeners.http = Arc::downgrade(&listener),
        ProxyProtocol::Socks5 => listeners.socks5 = Arc::downgrade(&listener),
    }
    listener
}

pub fn runtime_modes() -> serde_json::Value {
    let listeners = LISTENERS.lock().unwrap_or_else(|e| e.into_inner());
    let http = listeners.http.upgrade();
    let socks5 = listeners.socks5.upgrade();
    let pool = [socks5.as_ref(), http.as_ref()].into_iter().flatten()
        .find_map(|listener| listener.pools.as_ref())
        .and_then(|pool| pool.current_load())
        .map(|(ready, flows)| serde_json::json!({ "ready": ready, "flows": flows }));
    serde_json::json!({
        "socks5": socks5.map(|listener| listener.mode),
        "http": http.map(|listener| listener.mode),
        "pool": pool,
    })
}

/// Lightweight handle passed to each connection handler.
/// Contains everything needed to route traffic through the VPN tunnel.
pub struct ProxyHandle {
    pub server_host: String,
    pub server_port: u16,
    pub server_path: String,
    pub tls_fingerprint: TlsFingerprint,
    pub sni_hostname: Option<String>,
    pub identity_key: Arc<IdentityKey>,
    pub server_bundle: Arc<X3DHPublicBundle>,
    pub server_identity: ServerIdentityConfig,
    pub split_tunnel: Arc<SplitTunnel>,
    /// Tunnel mode: legacy per-flow, single multiplexed pipe, or pooled.
    pub mode: Socks5Mode,
    pub mux_path: String,
    pub mux_tunnel: Arc<Mutex<Option<Arc<Socks5Tunnel>>>>,
    /// Per-exit tunnel pools; only populated in pooled mode.
    pub tunnel_pools: Option<Arc<TunnelPools>>,
    /// Registry of all configured servers keyed by name. In legacy and
    /// pooled modes the router below picks which exit carries the flow.
    pub pool: Arc<ServerPool>,
    /// Domain/IP → server-name matcher. `choose(host)` returns `"default"`
    /// when nothing overrides.
    pub router: Arc<Router>,
}

/// Parse target address into host and port.
pub fn parse_target(target: &str) -> Result<(String, u16)> {
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid target format"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port"))?;
    Ok((host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host).to_string(), port))
}

/// Enable TCP keepalive on an accepted client socket.
///
/// LAN peers regularly die without sending FIN/RST — phones roaming between
/// Wi-Fi and cellular, upstream NAT rebinds, laptops sleeping mid-connection.
/// Without keepalive the kernel never notices, the socket stays ESTABLISHED
/// forever, and the flow built on top of it (including its WebSocket to the
/// server) is pinned forever. With keepalive the dead peer surfaces as a
/// read error within ~2 minutes and normal teardown runs.
pub fn enable_tcp_keepalive(stream: TcpStream) -> std::io::Result<TcpStream> {
    let std_stream = stream.into_std()?;
    let socket = socket2::Socket::from(std_stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(60))
        .with_interval(std::time::Duration::from_secs(10));
    socket.set_tcp_keepalive(&keepalive)?;
    let std_stream = std::net::TcpStream::from(socket);
    std_stream.set_nonblocking(true)?;
    TcpStream::from_std(std_stream)
}

/// Encode target address for server.
/// Format: [host_len: u8][host_bytes][port: u16_be]
pub fn encode_target_address(target: &str) -> Result<Vec<u8>> {
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid target address format, expected host:port"))?;

    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port number: {}", port_str))?;

    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(anyhow::anyhow!("Hostname too long"));
    }

    let mut result = Vec::with_capacity(1 + host_bytes.len() + 2);
    result.push(host_bytes.len() as u8);
    result.extend_from_slice(host_bytes);
    result.extend_from_slice(&port.to_be_bytes());

    Ok(result)
}

#[derive(Clone, Copy)]
pub enum ProxyProtocol {
    Http,
    Socks5,
}

struct ConnectionTiming {
    stage: &'static str,
    since: std::time::Instant,
    stages: Vec<(&'static str, u128)>,
    reused: Option<bool>,
}

impl ConnectionTiming {
    fn finish_stage(&mut self, next: &'static str) {
        let now = std::time::Instant::now();
        self.stages.push((self.stage, (now - self.since).as_millis()));
        self.stage = next;
        self.since = now;
    }
}

/// Count successful writes as they happen and preserve TCP half-close semantics.
async fn copy_direct(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    mut writer: impl tokio::io::AsyncWrite + Unpin,
    upload: bool,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return writer.shutdown().await;
        }
        let mut offset = 0;
        while offset < n {
            let written = writer.write(&buf[offset..n]).await?;
            if written == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            offset += written;
            crate::dashboard::record_bypass_bytes(written as u64, upload);
        }
    }
}

/// Open a routed stream only after the destination has accepted the connection.
pub async fn open_target(
    host: &str,
    port: u16,
    proxy: &ProxyHandle,
    protocol: Option<ProxyProtocol>,
) -> Result<tokio::io::DuplexStream> {
    crate::dashboard::record_conn_accepted();
    let started = std::time::Instant::now();
    let mut timing = ConnectionTiming {
        stage: "分流",
        since: started,
        stages: Vec::with_capacity(3),
        reused: None,
    };
    let mut route = None;
    let attempt = async {
        let (decision, reason, addresses, gfwlist) = proxy.split_tunnel.connection_route(host).await;
        route = Some((decision, reason));
        open_target_inner(host, port, proxy, decision, &addresses, gfwlist, &mut timing).await
    };
    let result = tokio::time::timeout(Duration::from_secs(30), attempt)
        .await
        .unwrap_or_else(|_| Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut, "target connection timed out"
        ).into()));
    if let Some(protocol) = protocol {
        timing.finish_stage("");
        let diagnostics = crate::dashboard::ProxyDiagnostics {
            stages: timing.stages,
            failed_stage: result.as_ref().err()
                .and_then(|error| error.downcast_ref::<crate::websocket::ConnectStage>())
                .map(|stage| stage.0),
            mode: route.filter(|(decision, _)| *decision == RoutingDecision::Tunnel)
                .map(|_| proxy.mode),
            reused: timing.reused,
        };
        crate::dashboard::record_proxy_connection(
            host, port, protocol, route, result.is_ok(), started.elapsed(), diagnostics,
        );
    }
    result
}

async fn open_target_inner(
    host: &str,
    port: u16,
    proxy: &ProxyHandle,
    decision: RoutingDecision,
    addresses: &[std::net::IpAddr],
    gfwlist: bool,
    timing: &mut ConnectionTiming,
) -> Result<tokio::io::DuplexStream> {
    let (client, relay_socket) = tokio::io::duplex(64 * 1024);
    match decision {
        RoutingDecision::Block => {
            crate::dashboard::record_conn_blocked();
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "blocked by routing policy",
            )
            .into());
        }
        RoutingDecision::Bypass => {
            crate::dashboard::record_conn_bypassed();
            timing.finish_stage("目标连接");
            let remote = crate::websocket::connect_direct_tcp(host, port, addresses).await?;
            let active = crate::dashboard::ActiveConnection::start();
            tokio::spawn(async move {
                let _active = active;
                let (local_read, local_write) = tokio::io::split(relay_socket);
                let (remote_read, remote_write) = remote.into_split();
                if let Err(e) = tokio::try_join!(
                    copy_direct(local_read, remote_write, true),
                    copy_direct(remote_read, local_write, false),
                ) {
                    debug!("Direct relay ended: {e}");
                }
            });
        }
        RoutingDecision::Tunnel => {
            crate::dashboard::record_conn_tunneled(gfwlist);
            timing.finish_stage("获取隧道");
            if proxy.mode == Socks5Mode::Legacy {
                timing.reused = Some(false);
                open_legacy(relay_socket, host, port, proxy, timing).await?;
            } else {
                let (tunnel, reused) = if proxy.mode == Socks5Mode::Pooled {
                    pooled_tunnel(host, proxy).await?
                } else {
                    multiplexed_tunnel(proxy).await?
                };
                timing.reused = Some(reused);
                timing.finish_stage("目标连接");
                let flow = tunnel.open_flow(host, port).await?;
                let active = crate::dashboard::ActiveConnection::start();
                tokio::spawn(async move {
                    let _active = active;
                    socks5_tunnel::relay_flow(relay_socket, flow, &tunnel).await;
                });
            }
        }
    }
    Ok(client)
}

/// Route an established local stream for library callers that handle their own handshake.
#[allow(dead_code)]
pub async fn route_connection(
    mut socket: TcpStream,
    _addr: std::net::SocketAddr,
    target: &str,
    proxy: &ProxyHandle,
) -> Result<()> {
    let (host, port) = parse_target(target)?;
    let mut remote = open_target(&host, port, proxy, None).await?;
    tokio::io::copy_bidirectional(&mut socket, &mut remote).await?;
    Ok(())
}

async fn multiplexed_tunnel(proxy: &ProxyHandle) -> Result<(Arc<Socks5Tunnel>, bool)> {
    let tunnel = {
        let mux_path = if proxy.mux_path.is_empty() {
            let base = proxy.server_path.trim_end_matches('/');
            if base.ends_with("/mux") {
                base.to_string()
            } else {
                format!("{}/mux", base)
            }
        } else {
            proxy.mux_path.clone()
        };
        debug!("MUX path derived: '{}'", mux_path);
        let mut guard = proxy.mux_tunnel.lock().await;

        if let Some(ref t) = *guard {
            if !t.is_alive() {
                warn!("Multiplexed tunnel receive loop is dead — reconnecting");
                *guard = None;
            }
        }

        let reused = guard.is_some();
        if guard.is_none() {
            // Retry tunnel creation up to 3 times if it dies immediately
            // (e.g. server closes connection right after X3DH)
            const MAX_TUNNEL_RETRIES: u32 = 3;
            let mut last_err = None;
            // The multiplexed tunnel always dials the default exit; its
            // resumption store lets these retries (and later reconnects)
            // resume the TLS session instead of doing full handshakes.
            let default_server = proxy
                .pool
                .get_or_default(crate::server_pool::DEFAULT_SERVER_NAME);
            for attempt in 1..=MAX_TUNNEL_RETRIES {
                let t = match Socks5Tunnel::connect(
                    &proxy.server_host,
                    proxy.server_port,
                    &mux_path,
                    proxy.tls_fingerprint,
                    proxy.sni_hostname.as_deref(),
                    &proxy.identity_key,
                    &proxy.server_bundle,
                    Some(&proxy.server_identity),
                    Some(&default_server.resumption),
                )
                .await
                {
                    Ok(t) => t,
                    Err(e) => {
                        warn!("Tunnel creation attempt {}/{} failed: {}", attempt, MAX_TUNNEL_RETRIES, e);
                        last_err = Some(e);
                        if attempt < MAX_TUNNEL_RETRIES {
                            tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
                        }
                        continue;
                    }
                };

                // Give the tunnel a moment to detect early death
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                if !t.is_alive() {
                    warn!("Tunnel died within 200ms of creation (attempt {}/{}), retrying",
                          attempt, MAX_TUNNEL_RETRIES);
                    last_err = Some(anyhow::anyhow!("Tunnel died immediately after creation"));
                    if attempt < MAX_TUNNEL_RETRIES {
                        tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
                    }
                    continue;
                }

                info!(
                    "Multiplexed tunnel connected to {}:{}{} (attempt {})",
                    proxy.server_host, proxy.server_port, mux_path, attempt
                );
                *guard = Some(t);
                last_err = None;
                break;
            }
            if guard.is_none() {
                return Err(last_err.unwrap_or_else(|| anyhow::anyhow!(
                    "Failed to create multiplexed tunnel after {} attempts", MAX_TUNNEL_RETRIES
                ))).context(format!("Failed to create multiplexed tunnel (mux_path='{}')", mux_path));
            }
        }
        (Arc::clone(guard.as_ref().unwrap()), reused)
    };

    Ok(tunnel)
}

async fn pooled_tunnel(target_host: &str, proxy: &ProxyHandle) -> Result<(Arc<Socks5Tunnel>, bool)> {
    let pools = proxy
        .tunnel_pools
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("pooled mode requires tunnel pools"))?;
    proxy.pool.connect_exit(proxy.router.choose(target_host), |server| async move {
        pools.get_or_default(&server.name).pick_with_reuse().await
    }).await
}

async fn open_legacy(
    socket: tokio::io::DuplexStream,
    target_host: &str,
    port: u16,
    proxy: &ProxyHandle,
    timing: &mut ConnectionTiming,
) -> Result<()> {
    let (mut relay, mut ws_reader, ws_writer, ws_tasks) = proxy.pool
        .connect_exit(proxy.router.choose(target_host), |server| async move {
            StreamRelay::connect(
                &server.host, server.port, &server.path, proxy.tls_fingerprint,
                server.sni_hostname.as_deref(), &proxy.identity_key, &server.bundle,
                Some(&server.identity_config), Some(&server.resumption),
            ).await
        }).await?;

    timing.finish_stage("目标连接");
    let mut request = vec![0]; // Confirmed TCP connect command. Older servers reject it.
    request.extend(encode_target_address(&format!("{target_host}:{port}"))?);
    relay.send_frame(&ws_writer, &request).await?;
    let status = relay
        .recv_frame(&mut ws_reader)
        .await
        .context("legacy server did not confirm target connection")?;
    anyhow::ensure!(status == [0], "legacy server could not connect to target");
    let active = crate::dashboard::ActiveConnection::start();
    tokio::spawn(async move {
        let _active = active;
        if let Err(e) = relay.relay(socket, ws_reader, ws_writer).await {
            debug!("Legacy relay ended: {e}");
        }
        ws_tasks.shutdown().await;
    });
    Ok(())
}
