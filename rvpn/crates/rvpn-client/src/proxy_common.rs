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

/// Open a routed stream only after the destination has accepted the connection.
pub async fn open_target(
    host: &str,
    port: u16,
    proxy: &ProxyHandle,
) -> Result<tokio::io::DuplexStream> {
    tokio::time::timeout(
        Duration::from_secs(30),
        open_target_inner(host, port, proxy),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "target connection timed out"))?
}

async fn open_target_inner(
    host: &str,
    port: u16,
    proxy: &ProxyHandle,
) -> Result<tokio::io::DuplexStream> {
    crate::dashboard::record_conn_accepted();
    let (decision, _, addresses) = proxy.split_tunnel.explain_connection(host).await;
    let (client, mut relay_socket) = tokio::io::duplex(64 * 1024);
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
            let mut remote = crate::websocket::connect_direct_tcp(host, port, &addresses).await?;
            tokio::spawn(async move {
                match tokio::io::copy_bidirectional(&mut relay_socket, &mut remote).await {
                    Ok((up, down)) => {
                        crate::dashboard::record_bytes_up(up);
                        crate::dashboard::record_bytes_down(down);
                    }
                    Err(e) => debug!("Direct relay ended: {e}"),
                }
                crate::dashboard::record_conn_completed();
            });
        }
        RoutingDecision::Tunnel => {
            crate::dashboard::record_conn_tunneled();
            if proxy.mode == Socks5Mode::Legacy {
                open_legacy(relay_socket, host, port, proxy).await?;
            } else {
                let tunnel = if proxy.mode == Socks5Mode::Pooled {
                    pooled_tunnel(host, proxy).await?
                } else {
                    multiplexed_tunnel(proxy).await?
                };
                let flow = tunnel.open_flow(host, port).await?;
                tokio::spawn(async move {
                    socks5_tunnel::relay_flow(relay_socket, flow, &tunnel).await;
                    crate::dashboard::record_conn_completed();
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
    let mut remote = open_target(&host, port, proxy).await?;
    tokio::io::copy_bidirectional(&mut socket, &mut remote).await?;
    Ok(())
}

async fn multiplexed_tunnel(proxy: &ProxyHandle) -> Result<Arc<Socks5Tunnel>> {
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
        Arc::clone(guard.as_ref().unwrap())
    };

    Ok(tunnel)
}

async fn pooled_tunnel(target_host: &str, proxy: &ProxyHandle) -> Result<Arc<Socks5Tunnel>> {
    let pools = proxy
        .tunnel_pools
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("pooled mode requires tunnel pools"))?;
    let exit_name = proxy.router.choose(target_host);
    let tunnel = pools
        .get_or_default(exit_name)
        .pick_tunnel()
        .await
        .with_context(|| format!("Failed to pick pooled tunnel via exit '{}'", exit_name))?;

    if exit_name != crate::server_pool::DEFAULT_SERVER_NAME {
        debug!("Routing {} → exit '{}' (pooled)", target_host, exit_name);
    }

    Ok(tunnel)
}

async fn open_legacy(
    socket: tokio::io::DuplexStream,
    target_host: &str,
    port: u16,
    proxy: &ProxyHandle,
) -> Result<()> {
    let server = proxy.pool.get_or_default(proxy.router.choose(target_host));

    if server.name != crate::server_pool::DEFAULT_SERVER_NAME {
        debug!(
            "Routing {} → server '{}' ({}:{})",
            target_host, server.name, server.host, server.port
        );
    }

    let (mut relay, mut ws_reader, ws_writer, ws_tasks) = StreamRelay::connect(
        &server.host,
        server.port,
        &server.path,
        proxy.tls_fingerprint,
        server.sni_hostname.as_deref(),
        &proxy.identity_key,
        &server.bundle,
        Some(&server.identity_config),
        Some(&server.resumption),
    )
    .await
    .with_context(|| format!("Failed to connect StreamRelay to server '{}'", server.name))?;

    let mut request = vec![0]; // Confirmed TCP connect command. Older servers reject it.
    request.extend(encode_target_address(&format!("{target_host}:{port}"))?);
    relay.send_frame(&ws_writer, &request).await?;
    let status = relay
        .recv_frame(&mut ws_reader)
        .await
        .context("legacy server did not confirm target connection")?;
    anyhow::ensure!(status == [0], "legacy server could not connect to target");
    tokio::spawn(async move {
        if let Err(e) = relay.relay(socket, ws_reader, ws_writer).await {
            debug!("Legacy relay ended: {e}");
        }
        ws_tasks.shutdown().await;
        crate::dashboard::record_conn_completed();
    });
    Ok(())
}
