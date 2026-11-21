// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// WebSocket connection utilities
//
// Chrome-like TLS (BoringSSL) + Chrome-like WebSocket upgrade headers (15 headers).
// The traffic profile matches a real Chrome 131 browser connecting to a WebSocket endpoint.

use anyhow::{Context as _, Result};
use futures::SinkExt;
use rand::{Rng, SeedableRng};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio_tungstenite::WebSocketStream;
use tungstenite::handshake::client::generate_key;
use tracing::trace;

pub use tungstenite::Message;

#[cfg(not(target_os = "android"))]
use rvpn_tls::{connect_boring_over_tcp, ChromeTlsStream, ResumptionStore, TlsFingerprint};

/// WebSocket reader type (receives messages)
pub type WebSocketReader = tokio::sync::mpsc::Receiver<Message>;

/// Capacity of the bounded channels created by [`split_websocket`].
///
/// Bounded on purpose: with unbounded channels a stalled local consumer let
/// the reader task ACK the server at line rate while frames piled up in
/// memory (~5 MB/h leak on long-running clients). The bound makes
/// backpressure reach TCP instead of the heap.
const WS_CHANNEL_CAPACITY: usize = 256;

/// Endpoint DNS and ECH policy are updated together on configuration reload.
#[cfg(not(target_os = "android"))]
#[derive(Clone)]
struct EndpointDns {
    resolver: Option<std::sync::Arc<crate::dns_cache::DnsResolver>>,
    ech_resolver: Option<std::sync::Arc<crate::dns_cache::DnsResolver>>,
    ech_mode: crate::config::EchMode,
    bypass: Option<std::sync::Weak<crate::split_tunnel::SplitTunnel>>,
}

#[cfg(not(target_os = "android"))]
static ENDPOINT_DNS: std::sync::RwLock<EndpointDns> = std::sync::RwLock::new(EndpointDns {
    resolver: None,
    ech_resolver: None,
    ech_mode: crate::config::EchMode::Off,
    bypass: None,
});

#[cfg(not(target_os = "android"))]
fn endpoint_dns() -> EndpointDns {
    ENDPOINT_DNS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[cfg(not(target_os = "android"))]
fn doh_nameservers(servers: &[String]) -> Vec<String> {
    servers.iter().filter(|server| {
        server.split_once("://").is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
    }).cloned().collect()
}

#[cfg(not(target_os = "android"))]
pub fn configure_endpoint_dns(client_config: &crate::config::ClientConfig) -> Result<()> {
    let config = &client_config.network;
    let nameservers = &client_config.dns_proxy.nameservers;
    let build_resolver = |servers: &[String]| {
        crate::dns_cache::DnsResolver::new(
            config.dns_cache_enabled,
            config.dns_cache_ttl,
            config.dns_cache_size,
            config.ipv6_enabled,
            false, // Prefer IPv6 when enabled.
            vec![],
        ).with_nameservers(servers).map(std::sync::Arc::new)
    };
    let resolver = build_resolver(nameservers)?;
    let ech_resolver = if config.ech_mode != crate::config::EchMode::Off {
        let servers = doh_nameservers(nameservers);
        if servers.is_empty() {
            None
        } else if servers.len() == nameservers.len() {
            Some(resolver.clone())
        } else {
            Some(build_resolver(&servers)?)
        }
    } else {
        None
    };
    *ENDPOINT_DNS.write().unwrap_or_else(|e| e.into_inner()) = EndpointDns {
        resolver: Some(resolver),
        ech_resolver,
        ech_mode: config.ech_mode,
        bypass: None,
    };
    Ok(())
}

#[cfg(not(target_os = "android"))]
pub(crate) fn set_server_bypass(split: &std::sync::Arc<crate::split_tunnel::SplitTunnel>) {
    ENDPOINT_DNS.write().unwrap_or_else(|e| e.into_inner()).bypass = Some(std::sync::Arc::downgrade(split));
}

#[cfg(target_os = "linux")]
type EndpointRouteHook = std::sync::Arc<dyn Fn(std::net::IpAddr) -> Result<()> + Send + Sync>;

#[cfg(target_os = "linux")]
static ENDPOINT_ROUTE_HOOK: std::sync::Mutex<Option<EndpointRouteHook>> = std::sync::Mutex::new(None);

#[cfg(target_os = "linux")]
pub fn set_endpoint_route_hook(hook: Option<EndpointRouteHook>) {
    *ENDPOINT_ROUTE_HOOK.lock().unwrap_or_else(|e| e.into_inner()) = hook;
}

#[cfg(not(target_os = "android"))]
async fn remember_server_addresses(dns: &EndpointDns, host: &str, addresses: &[std::net::SocketAddr]) {
    if let Some(split) = dns.bypass.as_ref().and_then(std::sync::Weak::upgrade) {
        split.set_server_ips(host, &addresses.iter().map(|address| address.ip()).collect::<Vec<_>>()).await;
    }
}

#[cfg(not(target_os = "android"))]
fn pin_endpoint_routes(addresses: &[std::net::SocketAddr]) -> Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(hook) = ENDPOINT_ROUTE_HOOK.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        for address in addresses { hook(address.ip())?; }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = addresses;
    Ok(())
}

#[cfg(not(target_os = "android"))]
#[derive(Debug)]
pub(crate) struct ConnectStage(pub &'static str);

#[cfg(not(target_os = "android"))]
impl std::fmt::Display for ConnectStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed", self.0)
    }
}

#[cfg(not(target_os = "android"))]
pub(crate) async fn connect_stage<T, E>(
    stage: &'static str,
    limit: Duration,
    operation: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    let started = std::time::Instant::now();
    let result = match tokio::time::timeout(limit, operation).await {
        Ok(result) => result.map_err(Into::into),
        Err(_) => Err(anyhow::anyhow!("timed out after {}s", limit.as_secs())),
    };
    let elapsed_ms = started.elapsed().as_millis() as u64;
    match &result {
        Ok(_) => tracing::debug!(stage, elapsed_ms, "VPN connection stage completed"),
        Err(error) => tracing::warn!(
            stage, elapsed_ms, error = %format_args!("{error:#}"), "VPN connection stage failed"
        ),
    }
    result.context(ConnectStage(stage))
}

/// Direct connections use the configured DoH resolver too, avoiding a second
/// hostname lookup by the OS after a split-tunnel decision.
#[cfg(not(target_os = "android"))]
pub async fn connect_direct_tcp(
    host: &str,
    port: u16,
    addresses: &[std::net::IpAddr],
) -> Result<tokio::net::TcpStream> {
    if !addresses.is_empty() {
        let targets: Vec<_> = addresses.iter().map(|ip| std::net::SocketAddr::new(*ip, port)).collect();
        return Ok(tokio::net::TcpStream::connect(targets.as_slice()).await?);
    }
    let dns = endpoint_dns();
    if let Some(resolver) = &dns.resolver {
        let addresses = resolver.resolve(host, port).await?;
        remember_server_addresses(&dns, host, &addresses).await;
        Ok(tokio::net::TcpStream::connect(addresses.as_slice()).await?)
    } else {
        Ok(tokio::net::TcpStream::connect((host, port)).await?)
    }
}

#[cfg(not(target_os = "android"))]
#[derive(Debug)]
struct SharedAddressFailure;

#[cfg(not(target_os = "android"))]
impl std::fmt::Display for SharedAddressFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VPN endpoint address lookup failed for both TLS paths")
    }
}

#[cfg(not(target_os = "android"))]
async fn with_ech_fallback<T>(
    ech: impl std::future::Future<Output = Result<T>>,
    ordinary_tls: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match ech.await {
        Ok(connection) => { crate::dashboard::record_tls_status("ECH".into()); Ok(connection) },
        Err(error) if error.is::<SharedAddressFailure>() => Err(error),
        Err(error) => {
            tracing::warn!("ECH unavailable; retrying with standard TLS: {error:#}");
            let connection = ordinary_tls.await?;
            crate::dashboard::record_tls_status(format!("普通 TLS，ECH 回退原因：{error:#}"));
            Ok(connection)
        }
    }
}

/// WebSocket writer type (sends messages)
#[derive(Clone)]
pub struct WebSocketWriter {
    sender: tokio::sync::mpsc::Sender<Message>,
}

impl WebSocketWriter {
    /// Send a message to the WebSocket writer task.
    ///
    /// Async because the channel is bounded: when the writer task is
    /// backpressured by a slow TCP connection, this awaits until there is
    /// capacity, propagating that backpressure to the caller.
    pub async fn send(&self, msg: Message) -> Result<()> {
        self.sender
            .send(msg)
            .await
            .map_err(|_| anyhow::anyhow!("WebSocket sender closed"))?;
        Ok(())
    }

    /// Check if the underlying channel has been closed (writer task exited)
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Build a writer directly from a channel sender (tests only).
    #[cfg(test)]
    pub(crate) fn from_sender(sender: tokio::sync::mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

/// Handle for the helper tasks spawned by [`split_websocket`].
///
/// The reader, writer and ping tasks run independently of the relay tasks.
/// When a relay ends they must be told to stop: the ping task keeps sending
/// WebSocket pings, which holds the TCP connection open, and the server
/// counts those pings as activity, so neither side ever times the flow out.
/// A flow whose helper tasks outlive its relay leaks its full
/// TLS + WebSocket + ratchet stack forever ("zombie flow").
///
/// Call [`WebSocketTaskHandle::shutdown`] to stop the tasks and wait for
/// them. Dropping the handle without calling `shutdown` still signals the
/// tasks (without awaiting them) as a backstop for early-return paths.
pub struct WebSocketTaskHandle {
    shutdown_tx: broadcast::Sender<()>,
    joins: Vec<JoinHandle<()>>,
}

impl WebSocketTaskHandle {
    /// Signal all helper tasks to stop and wait for them to exit.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(());
        for join in std::mem::take(&mut self.joins) {
            let _ = join.await;
        }
    }
}

impl Drop for WebSocketTaskHandle {
    fn drop(&mut self) {
        // Drop is synchronous so the tasks cannot be awaited here, but the
        // signal alone guarantees they exit on their next poll and can no
        // longer keep a dead flow's socket alive.
        let _ = self.shutdown_tx.send(());
    }
}

/// Connect to WebSocket server using Chrome-fingerprinted TLS (boring) + manual WebSocket upgrade.
///
/// This replaces the previous tokio-tungstenite `connect_async` path (which used rustls and had
/// a distinctive non-Chrome TLS fingerprint). The boring-based path mimics Chrome TLS 1.3,
/// making the connection much harder for DPI/GFW to fingerprint and block.
///
/// The WebSocket upgrade request sends Chrome-like headers (15 headers matching Chrome 131)
/// so the traffic profile matches a real browser connecting to a WebSocket endpoint.
///
/// NOTE: We do NOT include `permessage-deflate` in Sec-WebSocket-Extensions. tungstenite 0.21
/// cannot handle compressed WebSocket frames — if the server negotiates compression, the
/// connection breaks with `Protocol(ResetWithoutClosingHandshake)`. Chrome sends this
/// extension because it has native deflate support; we don't.
///
/// `resumption` is the per-exit-server TLS session store: reconnects with the
/// same store offer the cached TLS 1.3 ticket (1-RTT resume, no certificate
/// flight) instead of a full handshake. `None` disables resumption.
#[cfg(not(target_os = "android"))]
pub async fn connect_websocket(
    host: &str,
    port: u16,
    path: &str,
    fingerprint: TlsFingerprint,
    sni_hostname: Option<&str>,
    resumption: Option<&ResumptionStore>,
) -> Result<WebSocketStream<ChromeTlsStream>> {
    let dns = endpoint_dns();
    let limit = Duration::from_secs(10);
    let origin = host.trim_end_matches('.');
    let sni = sni_hostname.unwrap_or(host).trim_end_matches('.');
    let ordinary_tls = async {
        let addresses = connect_stage("dns_address", limit, async {
            let target = origin.trim_matches(['[', ']']);
            if let Some(resolver) = &dns.resolver {
                resolver.resolve_endpoint(target, port).await
            } else {
                Ok(tokio::net::lookup_host((target, port)).await?.collect())
            }
        }).await?;
        remember_server_addresses(&dns, origin, &addresses).await;
        pin_endpoint_routes(&addresses)?;
        dial_tls(&addresses, fingerprint, sni, resumption, None).await
    };
    let tls_stream = if dns.ech_mode != crate::config::EchMode::Off {
        let ech = async {
            anyhow::ensure!(sni.eq_ignore_ascii_case(origin), "ECH uses the endpoint hostname as SNI");
            let resolver = dns.ech_resolver.as_ref().context("No DoH upstream configured for ECH")?;
            let (target, target_port, config) =
                connect_stage("dns_https", limit, resolver.resolve_ech(origin, port)).await?;
            let lookup = connect_stage("dns_address", limit, resolver.resolve_endpoint(&target, target_port)).await;
            let same_endpoint = target.trim_end_matches('.').eq_ignore_ascii_case(origin)
                && target_port == port
                && dns.resolver.as_ref().is_some_and(|ordinary| std::sync::Arc::ptr_eq(ordinary, resolver));
            let addresses = if same_endpoint { lookup.context(SharedAddressFailure)? } else { lookup? };
            remember_server_addresses(&dns, origin, &addresses).await;
            pin_endpoint_routes(&addresses)?;
            dial_tls(&addresses, fingerprint, sni, resumption, Some(&config)).await
        };
        if dns.ech_mode == crate::config::EchMode::Required {
            let connection = ech.await.inspect_err(|err| {
                crate::dashboard::record_tls_status(format!("强制 ECH 失败：{err:#}"));
            }).context("Required ECH connection failed")?;
            crate::dashboard::record_tls_status("ECH".into());
            connection
        } else {
            with_ech_fallback(ech, ordinary_tls).await?
        }
    } else {
        let connection = ordinary_tls.await?;
        crate::dashboard::record_tls_status("普通 TLS".into());
        connection
    };

    // Build Chrome-like WebSocket upgrade request with 15 headers.
    // Real Chrome 131 sends these on WebSocket upgrade — matching this profile makes
    // DPI/GFW traffic classification much harder.
    let ws_key = generate_key();
    let authority = format!("{}:{}", host, port);
    let url = format!("wss://{}:{}{}", host, port, path);
    let request = tungstenite::http::Request::builder()
        .method("GET")
        .uri(url)
        .header("Host", &authority)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", &ws_key)
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        )
        .header("Accept", "*/*")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("Sec-Fetch-Dest", "websocket")
        .header("Sec-Fetch-Mode", "websocket")
        .header("Sec-Fetch-Site", "same-origin")
        .body(())
        .context("Failed to build WebSocket upgrade request")?;

    // Perform WebSocket HTTP/1.1 upgrade over the existing boring TLS stream
    upgrade_websocket(request, tls_stream, limit).await
}

#[cfg(not(target_os = "android"))]
async fn upgrade_websocket<S: AsyncRead + AsyncWrite + Unpin>(
    request: tungstenite::http::Request<()>,
    stream: S,
    limit: Duration,
) -> Result<WebSocketStream<S>> {
    let (websocket, _) = connect_stage(
        "websocket_upgrade",
        limit,
        tokio_tungstenite::client_async(request, stream),
    )
    .await?;
    Ok(websocket)
}

#[cfg(not(target_os = "android"))]
async fn dial_tls(
    addresses: &[std::net::SocketAddr],
    fingerprint: TlsFingerprint,
    sni: &str,
    resumption: Option<&ResumptionStore>,
    ech_config: Option<&[u8]>,
) -> Result<ChromeTlsStream> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    let mut last_error = anyhow::anyhow!("No VPN endpoint addresses");
    for addr in addresses {
        let remaining = || deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining().is_zero() {
            break;
        }
        let tcp = match connect_stage(
            "tcp_connect",
            remaining().min(Duration::from_secs(4)),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(tcp) => tcp,
            Err(error) => {
                last_error = error;
                continue;
            }
        };
        match connect_stage(
            "tls_handshake",
            remaining(),
            connect_boring_over_tcp(tcp, fingerprint, sni, resumption, ech_config),
        )
        .await
        {
            Ok(tls) => return Ok(tls),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

/// Split WebSocket stream into reader and writer
///
/// Returns the reader, the writer, and a [`WebSocketTaskHandle`] controlling
/// the spawned helper tasks. The handle MUST be shut down (or dropped) when
/// the connection is no longer needed, otherwise the ping task keeps the
/// socket alive forever — see the handle's docs.
pub fn split_websocket<S>(
    ws_stream: WebSocketStream<S>,
) -> (WebSocketReader, WebSocketWriter, WebSocketTaskHandle)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use futures::stream::StreamExt;

    let (mut write, mut read) = ws_stream.split();

    let (tx_to_ws, mut rx_from_app) = tokio::sync::mpsc::channel::<Message>(WS_CHANNEL_CAPACITY);
    let (tx_to_app, rx_to_app) = tokio::sync::mpsc::channel::<Message>(WS_CHANNEL_CAPACITY);
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let closing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Writer task
    let writer_join = {
        let closing = closing.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = rx_from_app.recv() => match msg {
                        Some(msg) => {
                            if closing.load(std::sync::atomic::Ordering::Acquire) {
                                // Receiving Close queues tungstenite's automatic
                                // acknowledgement. Flush it, never send new data.
                                let _ = write.flush().await;
                                break;
                            }
                            let is_close = matches!(msg, Message::Close(_));
                            if is_close { closing.store(true, std::sync::atomic::Ordering::Release); }
                            if let Err(e) = write.send(msg).await {
                                match e {
                                    tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed
                                    | tungstenite::Error::Protocol(tungstenite::error::ProtocolError::SendAfterClosing) => tracing::debug!("WebSocket already closing"),
                                    other => tracing::error!("WebSocket send error: {}", other),
                                }
                                break;
                            }
                            if is_close { break; }
                        }
                        None => break,
                    },
                    _ = shutdown_rx.recv() => break,
                }
            }
            tracing::debug!("WebSocket writer task ending");
        })
    };

    // Ping task - sends WebSocket-level pings to keep connection alive.
    // Uses jittered intervals to avoid perfectly periodic traffic patterns
    // that statistical classifiers can detect.
    let ping_join = {
        let closing = closing.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        let ping_sender = tx_to_ws.clone();
        tokio::spawn(async move {
            let mut rng = rand::rngs::StdRng::from_entropy();
            // Random initial delay to avoid burst at connection start
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(rng.gen_range(5000..=8000))) => {}
                _ = shutdown_rx.recv() => {
                    tracing::debug!("WebSocket ping task ending");
                    return;
                }
            }
            loop {
                if closing.load(std::sync::atomic::Ordering::Acquire) { break; }
                // try_send on the bounded channel: a Full channel means the
                // writer is backpressured by TCP — skip this ping (the next
                // one in ~11s will get through) rather than block or break.
                match ping_sender.try_send(Message::Ping(vec![])) {
                    Ok(()) => {},
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        trace!("WebSocket channel full, skipping ping");
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        tracing::debug!("Ping sender closed, stopping ping task");
                        break;
                    }
                }
                // Jittered interval: 8-14s (nominal ~11s, matching Chrome behavior)
                let jitter_ms = rng.gen_range(8000..=14000);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(jitter_ms)) => {}
                    _ = shutdown_rx.recv() => break,
                }
            }
            tracing::debug!("WebSocket ping task ending");
        })
    };

    // Reader task - note: mpsc channel drops tx_to_app when task exits
    let reader_join = {
        let closing = closing.clone();
        let close_writer = tx_to_ws.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = read.next() => match result {
                        Some(Ok(msg)) => {
                            let is_close = matches!(msg, Message::Close(_));
                            if is_close {
                                closing.store(true, std::sync::atomic::Ordering::Release);
                                // Wake the writer to flush the automatic Close response.
                                let _ = close_writer.try_send(Message::Close(None));
                            }
                            if tx_to_app.send(msg).await.is_err() {
                                tracing::debug!("WebSocket reader: channel receiver dropped, exiting");
                                break;
                            }
                            if is_close { break; }
                        }
                        Some(Err(e)) => {
                            match e {
                                tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => tracing::debug!("WebSocket closed"),
                                other => tracing::error!("WebSocket receive error: {:?}, closing connection", other),
                            }
                            // Don't send anything - just let the task exit which drops the sender
                            break;
                        }
                        None => break,
                    },
                    _ = shutdown_rx.recv() => break,
                }
            }
            tracing::debug!("WebSocket reader task ending");
        })
    };

    let writer = WebSocketWriter { sender: tx_to_ws };
    let handle = WebSocketTaskHandle {
        shutdown_tx,
        joins: vec![reader_join, writer_join, ping_join],
    };
    (rx_to_app, writer, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[cfg(not(target_os = "android"))]
    #[tokio::test]
    async fn dial_time_dns_refresh_updates_server_bypass_addresses() {
        use crate::split_tunnel::{SplitTunnel, SplitTunnelConfig, RoutingDecision};
        let split = std::sync::Arc::new(SplitTunnel::new(
            SplitTunnelConfig { enabled: false, ..Default::default() },
            std::sync::Arc::new(crate::dns_cache::DnsResolver::new(true, 300, 1000, true, false, vec![])),
        ).await.unwrap());
        split.set_server_endpoints(&["vpn.example".into()]).await;
        let dns = EndpointDns { resolver: None, ech_resolver: None, ech_mode: crate::config::EchMode::Off, bypass: Some(std::sync::Arc::downgrade(&split)) };
        let old = "192.0.2.1:443".parse::<std::net::SocketAddr>().unwrap();
        let new = "[2001:db8::1]:8443".parse::<std::net::SocketAddr>().unwrap();
        remember_server_addresses(&dns, "VPN.EXAMPLE.", &[old]).await;
        assert_eq!(split.decide_by_ip(old.ip()).await, RoutingDecision::Bypass);
        remember_server_addresses(&dns, "vpn.example", &[new]).await;
        assert_eq!(split.decide_by_ip(new.ip()).await, RoutingDecision::Bypass);
        assert_eq!(split.decide_by_ip(old.ip()).await, RoutingDecision::Tunnel);
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn ech_uses_only_doh_from_the_shared_list() {
        let doh = "https://resolver.example/dns-query";
        let udp = "223.5.5.5:53";
        assert_eq!(doh_nameservers(&[udp.into(), doh.into()]), [doh]);
        assert!(doh_nameservers(&[udp.into()]).is_empty());
    }

    #[cfg(not(target_os = "android"))]
    #[tokio::test]
    async fn ech_falls_back_to_tls_when_lookup_or_handshake_fails() {
        let shared = with_ech_fallback::<()>(
            async { Err(anyhow::anyhow!("upstream unreachable").context(SharedAddressFailure)) },
            async { panic!("identical address lookup already failed") },
        ).await.unwrap_err();
        assert!(shared.is::<SharedAddressFailure>());
        for reason in ["missing HTTPS record", "ECH handshake rejected"] {
            let connection = with_ech_fallback(async { anyhow::bail!(reason) }, async { Ok("TLS") }).await;
            assert_eq!(connection.unwrap(), "TLS");
        }
        let connection = with_ech_fallback(async { Ok("ECH") }, async { panic!("ECH already succeeded") }).await;
        assert_eq!(connection.unwrap(), "ECH");
        let error = with_ech_fallback::<()>(
            async { anyhow::bail!("missing HTTPS record") },
            async { anyhow::bail!("ordinary TLS certificate rejected") },
        ).await.unwrap_err();
        assert_eq!(error.to_string(), "ordinary TLS certificate rejected");
    }

    #[cfg(not(target_os = "android"))]
    #[tokio::test]
    async fn websocket_upgrade_reports_rejection_and_allows_later_reconnect() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(4096);
        let request = || {
            tungstenite::client::IntoClientRequest::into_client_request(
                "wss://example.test/api/v1/ws",
            )
        };
        let denied = tokio::spawn(async move {
            let mut end = Vec::new();
            while !end.ends_with(b"\r\n\r\n") {
                end.push(server.read_u8().await.unwrap());
            }
            server
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let result = upgrade_websocket(request()?, client, Duration::from_secs(1)).await;
        let error = format!("{:#}", result.unwrap_err());
        assert!(
            error.contains("websocket_upgrade failed") && error.contains("403"),
            "{error}"
        );
        denied.await?;

        let (client, server) = tokio::io::duplex(4096);
        let echo = tokio::spawn(async move {
            let mut socket = tokio_tungstenite::accept_async(server).await?;
            let message = socket.next().await.unwrap()?;
            socket.send(message).await
        });
        let mut socket = upgrade_websocket(request()?, client, Duration::from_secs(1)).await?;
        socket.send(Message::Binary(vec![1, 2, 3])).await?;
        let received = tokio::time::timeout(Duration::from_secs(1), socket.next()).await?;
        assert_eq!(received.unwrap()?, Message::Binary(vec![1, 2, 3]));
        echo.await??;
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    #[tokio::test]
    async fn dns_timeout_surfaces_its_stage() {
        let result = connect_stage::<(), anyhow::Error>(
            "dns_address",
            Duration::ZERO,
            std::future::pending(),
        )
        .await;
        assert!(format!("{:#}", result.unwrap_err()).contains("dns_address failed: timed out"));
    }

    #[tokio::test]
    async fn peer_close_prevents_additional_data_and_completes_close_handshake() {
        let (client, server) = tokio::io::duplex(4096);
        let client = WebSocketStream::from_raw_socket(client,tungstenite::protocol::Role::Client,None).await;
        let mut server = WebSocketStream::from_raw_socket(server,tungstenite::protocol::Role::Server,None).await;
        let (mut reader, writer, tasks) = split_websocket(client);
        server.send(Message::Close(None)).await.unwrap();
        assert!(matches!(tokio::time::timeout(Duration::from_secs(1),reader.recv()).await.unwrap(),Some(Message::Close(_))));
        // Late application data and duplicate Close must never hit the wire.
        let _ = writer.send(Message::Binary(vec![1,2,3])).await;
        let _ = writer.send(Message::Close(None)).await;
        let reply = tokio::time::timeout(Duration::from_secs(1),server.next()).await.unwrap().unwrap().unwrap();
        assert!(matches!(reply,Message::Close(_)));
        tokio::time::timeout(Duration::from_secs(1),tasks.shutdown()).await.unwrap();
    }

    #[tokio::test]
    async fn local_close_stops_writer_and_ping_before_duplicate_close() {
        let (client, server) = tokio::io::duplex(4096);
        let client = WebSocketStream::from_raw_socket(client,tungstenite::protocol::Role::Client,None).await;
        let mut server = WebSocketStream::from_raw_socket(server,tungstenite::protocol::Role::Server,None).await;
        let (_reader, writer, tasks) = split_websocket(client);
        writer.send(Message::Close(None)).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(1),server.next()).await.unwrap().unwrap().unwrap();
        assert!(matches!(reply,Message::Close(_)));
        assert!(writer.is_closed());
        assert!(writer.send(Message::Ping(vec![])).await.is_err());
        tokio::time::timeout(Duration::from_secs(1),tasks.shutdown()).await.unwrap();
    }
}
