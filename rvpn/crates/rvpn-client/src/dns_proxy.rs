// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DNS-over-WebSocket proxy for desktop SOCKS5 mode
//
// Listens on UDP, forwards DNS queries through the server's encrypted /dns
// WebSocket endpoint. Maintains a persistent connection with auto-reconnect
// and supports concurrent queries via an internal query_id map.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use rvpn_core::crypto::{DoubleRatchet, IdentityKey, Signature, Verifier, VerifyingKey, X3DHPublicBundle};
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::crypto::ratchet::RatchetMessage;
use rvpn_core::protocol::HandshakeMessage;
use rvpn_core::protocol::message::{DnsQuery, DnsResponse};

use crate::dns_cache::DnsResolver;
use crate::split_tunnel::{RoutingDecision, SplitTunnel};
use rvpn_tls::{ResumptionStore, TlsFingerprint};
use crate::websocket::{connect_websocket, split_websocket, Message, WebSocketReader, WebSocketWriter};

/// Payload type bytes for DNS messages — must match server's DnsHandler
const DNS_QUERY_LIMIT: usize = 256;
const PAYLOAD_DNS_QUERY: u8 = 0x08;
const PAYLOAD_DNS_RESPONSE: u8 = 0x09;

/// Internal message type: (query, dns_txid_for_reply, client_addr, reply_channel)
type QueryMsg = (DnsQuery, u16, SocketAddr, oneshot::Sender<Option<DnsResponse>>);

struct WsManagerTask(tokio::task::JoinHandle<()>);

impl Drop for WsManagerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn receive_datagram(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buf).await {
            // Windows reports ICMP errors from earlier UDP replies on recv_from.
            // A client that closed its socket must not stop the DNS listener.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                debug!("DNS proxy: ignoring UDP peer error: {error}");
            }
            result => return result,
        }
    }
}

/// DNS-over-WebSocket proxy
///
/// Listens for UDP DNS queries on a local port and resolves them through
/// the VPN server's encrypted WebSocket `/dns` endpoint.
///
/// When split tunnel is enabled, bypass/block domains are handled locally
/// without touching the tunnel.
pub struct DnsProxy {
    listen_addr: SocketAddr,
    server_host: String,
    server_port: u16,
    /// Full path to the DNS endpoint, e.g. "/api/v1/ws/dns"
    server_dns_path: String,
    tls_fingerprint: TlsFingerprint,
    identity_key: Arc<IdentityKey>,
    server_bundle: Arc<X3DHPublicBundle>,
    split_tunnel: Arc<SplitTunnel>,
    next_id: AtomicU64,
    /// DNS resolver with caching for both local and tunnel responses
    dns_resolver: Arc<DnsResolver>,
    /// Explicit UDP/DoH upstreams for local queries (avoids loopback)
    nameservers: rvpn_split_tunnel::dns_cache::DnsUpstreams,
    /// Hostnames of all configured VPN servers (primary + extras), lowercased
    /// with any trailing dot stripped. Queries for these are always resolved
    /// locally — see the dispatch loop for why.
    server_hosts: Arc<Vec<String>>,
    /// DoH endpoints whose system DNS lookups may come back to this proxy.
    doh_hosts: Arc<Vec<String>>,
    /// TLS session resumption store for this proxy's server. Held for the
    /// proxy's lifetime so each WebSocket reconnect (`run_ws_manager` backoff
    /// loop) resumes the cached TLS 1.3 ticket instead of a full handshake.
    resumption: ResumptionStore,
}

impl DnsProxy {
    /// Create a new DNS proxy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        listen_addr: SocketAddr,
        server_host: String,
        server_port: u16,
        server_path: &str,
        tls_fingerprint: TlsFingerprint,
        identity_key: Arc<IdentityKey>,
        server_bundle: Arc<X3DHPublicBundle>,
        split_tunnel: Arc<SplitTunnel>,
        dns_resolver: Arc<DnsResolver>,
        nameservers: rvpn_split_tunnel::dns_cache::DnsUpstreams,
        extra_server_hosts: Vec<String>,
        doh_hosts: Vec<String>,
    ) -> Self {
        // Derive DNS path from base WebSocket path, stripping any mux/tun suffix
        let base_path = server_path.trim_end_matches('/');
        let base_path = base_path
            .strip_suffix("/mux")
            .or_else(|| base_path.strip_suffix("/tun"))
            .unwrap_or(base_path);
        let server_dns_path = format!("{}/dns", base_path);
        // Normalized hostnames of every VPN server this client may connect to.
        let mut server_hosts: Vec<String> =
            Vec::with_capacity(1 + extra_server_hosts.len());
        server_hosts.push(server_host.trim_end_matches('.').to_ascii_lowercase());
        server_hosts.extend(
            extra_server_hosts
                .iter()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase()),
        );
        Self {
            listen_addr,
            server_host,
            server_port,
            server_dns_path,
            tls_fingerprint,
            identity_key,
            server_bundle,
            split_tunnel,
            next_id: AtomicU64::new(1),
            dns_resolver,
            nameservers,
            server_hosts: Arc::new(server_hosts),
            doh_hosts: Arc::new(doh_hosts),
            resumption: ResumptionStore::new(),
        }
    }

    /// Start the DNS proxy (runs indefinitely, returns only on fatal error)
    #[allow(dead_code)] // Standalone entry point; the supervisor supplies a bound socket.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let socket = UdpSocket::bind(self.listen_addr)
                .await
                .with_context(|| format!("Failed to bind DNS proxy to {}", self.listen_addr))?;
        self.run_with_socket(socket).await
    }

    pub(crate) async fn run_with_socket(self: Arc<Self>, socket: UdpSocket) -> Result<()> {
        let listener = socket.local_addr()?;
        let socket = Arc::new(socket);

        info!("DNS proxy listening on {}", self.listen_addr);

        // Channel: UDP tasks → WebSocket connection manager
        let (query_tx, query_rx) = mpsc::channel::<QueryMsg>(DNS_QUERY_LIMIT);
        crate::dashboard::track_dns_queue(query_tx.downgrade());
        let workers = Arc::new(tokio::sync::Semaphore::new(DNS_QUERY_LIMIT));

        // WebSocket connection manager (runs in background, reconnects on failure)
        let self_clone = Arc::clone(&self);
        let _ws_manager = WsManagerTask(tokio::spawn(async move {
            self_clone.run_ws_manager(query_rx).await;
        }));

        // UDP receive loop
        // Receive complete EDNS datagrams to avoid WSAEMSGSIZE on Windows.
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = receive_datagram(&socket, &mut buf).await?;
            let Ok(permit) = workers.clone().try_acquire_owned() else {
                crate::dashboard::DNS_OVERLOAD.fetch_add(1, Ordering::Relaxed);
                if n >= 12 {
                    let reply = build_dns_servfail(&buf[..n], u16::from_be_bytes([buf[0], buf[1]]));
                    let _ = socket.send_to(&reply, src).await;
                }
                continue;
            };
            let data = buf[..n].to_vec();
            let socket_clone = Arc::clone(&socket);
            let query_tx_clone = query_tx.clone();
            let qid = self.next_id.fetch_add(1, Ordering::Relaxed);

            let split_tunnel_clone = Arc::clone(&self.split_tunnel);
            let dns_resolver_clone = Arc::clone(&self.dns_resolver);
            let nameservers_clone = self.nameservers.clone();
            let server_hosts_clone = Arc::clone(&self.server_hosts);
            let doh_hosts = Arc::clone(&self.doh_hosts);
            tokio::spawn(async move {
                let _permit = permit;
                let process = async {
                    match parse_dns_query(&data) {
                        Ok((dns_txid, domain, qtype)) => {
                            let query_start = Instant::now();
                            debug!("DNS query from {}: {} (type={})", src, domain, qtype);

                            // The VPN server hostnames themselves must never be
                            // resolved through the tunnel: the tunnel needs DNS to
                            // (re)connect, so tunneling these queries creates a
                            // circular dependency — after any disconnect, buffered
                            // queries wait for the tunnel while the tunnel waits
                            // for DNS, and the client never recovers. Resolve them
                            // locally via the same path as bypass domains.
                            let host = domain.trim_end_matches('.');
                            let is_doh_host = doh_hosts.iter().any(|name| name.eq_ignore_ascii_case(host));
                            let is_server_host = server_hosts_clone.iter().any(|name| name.eq_ignore_ascii_case(host));
                            let (decision, gfwlist) = if is_doh_host || is_server_host {
                                (RoutingDecision::Bypass, false)
                            } else {
                                split_tunnel_clone.decide_dns(&domain).await
                            };

                            let mut cache_hit = false;
                            let wire = 'answer: { match decision {
                                RoutingDecision::Bypass => {
                                    // Resolve locally — bypass domain should not go through tunnel
                                    debug!("DNS proxy: resolving {} locally (bypass)", domain);
                                    let result = if is_doh_host {
                                        nameservers_clone.query_bootstrap(&data, listener).await
                                    } else {
                                        resolve_locally(&data, &nameservers_clone).await
                                    };
                                    let wire = match result {
                                        Ok(wire) => {
                                            // Parse and cache successful bypass responses
                                            if let Ok((ips, ttl_secs)) = crate::dns_cache::parse_dns_a_response(&wire, dns_txid) {
                                                let ttl = std::time::Duration::from_secs(ttl_secs as u64);
                                                dns_resolver_clone.store_with_ttl(&domain, ips, ttl).await;
                                            }
                                            wire
                                        }
                                        Err(e) => {
                                            warn!("DNS proxy: local resolution failed for {}: {}", domain, e);
                                            build_dns_servfail(&data, dns_txid)
                                        }
                                    };
                                    wire
                                }
                                RoutingDecision::Block => {
                                    // Return NXDOMAIN — treat blocked ad/tracker as non-existent
                                    debug!("DNS proxy: blocking {} (ad/tracker)", domain);
                                    build_dns_nxdomain(&data, dns_txid)
                                }
                                RoutingDecision::Tunnel => {
                                    // Non-address record types (NS/TXT/MX/HTTPS/...)
                                    // cannot be represented by the tunnel DNS protocol
                                    // (server answers via getaddrinfo — A/AAAA only).
                                    // Resolve them locally with a raw UDP forward so
                                    // diagnostic tools (dig) and HTTPS-RR clients get
                                    // real answers instead of empty NODATA/SERVFAIL.
                                    // A/AAAA — the record types CN resolvers poison
                                    // for connectivity — still go through the tunnel.
                                    if qtype != 1 && qtype != 28 {
                                        debug!("DNS proxy: resolving {} (type={}) locally (non-A/AAAA)", domain, qtype);
                                        let wire = match resolve_locally(
                                            &data, &nameservers_clone
                                        ).await {
                                            Ok(wire) => wire,
                                            Err(e) => {
                                                warn!("DNS proxy: local resolution failed for {} (type={}): {}", domain, qtype, e);
                                                build_dns_servfail(&data, dns_txid)
                                            }
                                        };
                                        wire
                                    } else {

                                    // The server has no IPv6 upstream and build_dns_response
                                    // strips AAAA records, so an AAAA query can only ever
                                    // produce an empty answer. Answer locally with an empty
                                    // NOERROR (NODATA) instead of spending a tunnel
                                    // round-trip — and during tunnel outages AAAA lookups
                                    // can no longer stall the client's resolver.
                                    if qtype == 28 {
                                        let response = DnsResponse {
                                            query_id: 0,
                                            success: true,
                                            ipv4_addrs: vec![],
                                            ipv6_addrs: vec![],
                                            ttl: 300,
                                            error: None,
                                        };
                                        let wire = build_dns_response(&data, dns_txid, &response);
                                        break 'answer wire;
                                    }

                                    // Check local cache before forwarding through tunnel.
                                    // A queries only: cached A data must never answer a
                                    // non-A question (HTTPS/TXT/etc. would get A records).
                                    if qtype == 1 {
                                        if let Some(ips) = dns_resolver_clone.lookup_cached(&domain).await {
                                            debug!("DNS proxy: cache hit for {}, skipping tunnel", domain);
                                            let ipv4_addrs: Vec<std::net::Ipv4Addr> = ips
                                                .iter()
                                                .filter_map(|ip| match ip {
                                                    IpAddr::V4(v4) => Some(*v4),
                                                    _ => None,
                                                })
                                                .collect();
                                            // Use the actual remaining TTL from the cache entry
                                            let ttl = dns_resolver_clone.get_remaining_ttl(&domain).await.unwrap_or(14400);
                                            let response = DnsResponse {
                                                query_id: 0,
                                                success: true,
                                                ipv4_addrs,
                                                ipv6_addrs: vec![],
                                                ttl,
                                                error: None,
                                            };
                                            let wire = build_dns_response(&data, dns_txid, &response);
                                            cache_hit = true;
                                            break 'answer wire;
                                        }
                                    }

                                    // Forward through encrypted WebSocket tunnel
                                    let query = DnsQuery {
                                        query_id: qid,
                                        domain: domain.clone(),
                                        query_type: qtype,
                                    };
                                    let (reply_tx, reply_rx) = oneshot::channel();
                                    if query_tx_clone.try_send((query, dns_txid, src, reply_tx)).is_err() {
                                        crate::dashboard::DNS_OVERLOAD.fetch_add(1, Ordering::Relaxed);
                                        break 'answer build_dns_servfail(&data, dns_txid);
                                    }
                                    // 5s timeout — if the WebSocket is zombie (protocol alive but
                                    // server not responding), don't hang the DNS client forever.
                                    let wire = match tokio::time::timeout(tokio::time::Duration::from_secs(5), reply_rx).await {
                                        // Propagate resolution failure as SERVFAIL
                                        // instead of a NOERROR with no answers —
                                        // NODATA wrongly tells stubs the name
                                        // exists but has no such record.
                                        Ok(Ok(Some(r))) if r.success => build_dns_response(&data, dns_txid, &r),
                                        _ => build_dns_servfail(&data, dns_txid),
                                    };
                                    wire
                                    }
                                }
                            }};
                            use crate::dashboard::DnsDecision;
                            let route = match decision {
                                RoutingDecision::Block => DnsDecision::Block,
                                RoutingDecision::Tunnel if qtype == 1 => DnsDecision::Tunnel,
                                _ => DnsDecision::Bypass,
                            };
                            crate::dashboard::record_dns_answer(&domain, qtype, route, cache_hit, gfwlist, query_start.elapsed(), &wire);
                            if let Err(e) = socket_clone.send_to(&wire, src).await {
                                debug!("DNS proxy: failed to send response to {}: {}", src, e);
                            }
                        }
                        Err(e) => {
                            warn!("DNS proxy: failed to parse query from {}: {}", src, e);
                        }
                    }
                };
                if tokio::time::timeout(std::time::Duration::from_secs(10), process).await.is_err() && data.len() >= 12 {
                    let _ = socket_clone.send_to(&build_dns_servfail(&data, u16::from_be_bytes([data[0],data[1]])), src).await;
                }
            });
        }
    }

    /// Connection manager loop — reconnects on failure with exponential backoff
    async fn run_ws_manager(self: Arc<Self>, mut query_rx: mpsc::Receiver<QueryMsg>) {
        let mut backoff_secs: u64 = 2;

        loop {
            match self.run_ws_session(&mut query_rx).await {
                Ok(_) => {
                    info!(
                        "DNS proxy: WebSocket closed, reconnecting in {}s...",
                        backoff_secs
                    );
                    backoff_secs = 2; // reset on clean close
                }
                Err(e) => {
                    warn!(
                        "DNS proxy: WebSocket error: {:#}, reconnecting in {}s...",
                        e, backoff_secs
                    );
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
            backoff_secs = (backoff_secs * 2).min(10);
        }
    }

    /// Single WebSocket session: connect, handshake, process queries until closed
    async fn run_ws_session(
        &self,
        query_rx: &mut mpsc::Receiver<QueryMsg>,
    ) -> Result<()> {
        let ws = connect_websocket(
            &self.server_host,
            self.server_port,
            &self.server_dns_path,
            self.tls_fingerprint,
            None,
            Some(&self.resumption),
        )
        .await
        .context("DNS proxy: WebSocket connect failed")?;

        // Split into reader/writer. The task handle is bound for the lifetime
        // of this tunnel run; its Drop signals the reader/writer/ping helper
        // tasks to stop when the run ends (reconnect or shutdown).
        let (mut reader, writer, _ws_tasks) = split_websocket(ws);

        let mut ratchet = crate::websocket::connect_stage(
            "x3dh_handshake",
            Duration::from_secs(15),
            dns_handshake(
                &mut reader,
                &writer,
                &self.identity_key,
                &self.server_bundle,
            ),
        )
        .await
        .context("DNS proxy: X3DH handshake failed")?;

        info!(
            "DNS proxy: connected to {}{}",
            self.server_host, self.server_dns_path
        );

        // Drain any stale queries that were buffered while disconnected.
        // Their UDP handlers have already timed out (5s), so responses
        // would be ignored anyway. Prevents stale burst on fresh connection.
        let mut drained = 0;
        while let Ok((_, _, _, reply_tx)) = query_rx.try_recv() {
            let _ = reply_tx.send(None);
            drained += 1;
        }
        if drained > 0 {
            warn!("DNS proxy: drained {} stale queries from disconnect buffer", drained);
        }

        /// Pending query with metadata needed for caching and timeout detection
        struct PendingQuery {
            tx: oneshot::Sender<Option<DnsResponse>>,
            domain: String,
            sent_at: Instant,
        }

        // Pending queries: query_id → pending query
        let mut pending: HashMap<u64, PendingQuery> = HashMap::new();

        // Persistent interval for checking pending query age. Using a persistent
        // interval (not tokio::time::sleep inside select!) ensures the check fires
        // regularly even when other branches (reader.recv, query_rx) fire frequently.
        // Tick at half the pending-timeout (10s) so an unanswered query is
        // detected within ~10-15s rather than up to 2x the threshold.
        let mut check_interval = tokio::time::interval(Duration::from_secs(5));
        check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // Outgoing: new DNS query from UDP handler
                msg = query_rx.recv(), if pending.len() < DNS_QUERY_LIMIT => {
                    match msg {
                        Some((query, _dns_txid, _src, reply_tx)) => {
                            if reply_tx.is_closed() { continue; }
                            let query_id = query.query_id;

                            let query_bytes = serde_json::to_vec(&query)
                                .context("DNS proxy: failed to serialize DnsQuery")?;

                            let encrypted = ratchet
                                .encrypt(&query_bytes, &[PAYLOAD_DNS_QUERY])
                                .map_err(|e| anyhow::anyhow!("DNS proxy: encrypt failed: {:?}", e))?;

                            let serialized = encrypted
                                .to_bytes()
                                .context("DNS proxy: failed to serialize RatchetMessage")?;

                            writer
                                .send(Message::Binary(serialized))
                                .await
                                .context("DNS proxy: failed to send query")?;

                            pending.insert(query_id, PendingQuery {
                                tx: reply_tx,
                                domain: query.domain,
                                sent_at: Instant::now(),
                            });
                        }
                        None => break, // channel closed (proxy shutting down)
                    }
                }

                // Incoming: response from server (with 120s read timeout as backstop)
                response = tokio::time::timeout(Duration::from_secs(120), reader.recv()) => {
                    match response {
                        Ok(Some(Message::Binary(data))) => {
                            let ratchet_msg = match RatchetMessage::from_bytes(&data) {
                                Ok(m) => m,
                                Err(e) => {
                                    warn!("DNS proxy: failed to parse RatchetMessage: {}", e);
                                    continue;
                                }
                            };

                            let plaintext = match ratchet.decrypt(&ratchet_msg, &[PAYLOAD_DNS_RESPONSE]) {
                                Ok(p) => p,
                                Err(e) => {
                                    warn!("DNS proxy: decryption failed: {:?}", e);
                                    continue;
                                }
                            };

                            let dns_response: DnsResponse = match serde_json::from_slice(&plaintext) {
                                Ok(r) => r,
                                Err(e) => {
                                    warn!("DNS proxy: failed to parse DnsResponse: {}", e);
                                    continue;
                                }
                            };

                            let qid = dns_response.query_id;
                            if let Some(pq) = pending.remove(&qid) {
                                // Cache successful responses to avoid redundant tunnel round-trips
                                if dns_response.success {
                                    let ips: Vec<IpAddr> = dns_response
                                        .ipv4_addrs
                                        .iter()
                                        .map(|ip| IpAddr::V4(*ip))
                                        .collect();
                                    let ttl = Duration::from_secs(dns_response.ttl as u64);
                                    self.dns_resolver.store_with_ttl(&pq.domain, ips, ttl).await;
                                }
                                let _ = pq.tx.send(Some(dns_response));
                            }
                        }
                        Ok(Some(Message::Close(_))) | Ok(None) => {
                            // Fail all pending queries so their UDP handlers can send SERVFAIL
                            for (_, pq) in pending.drain() {
                                let _ = pq.tx.send(None);
                            }
                            break;
                        }
                        Ok(Some(_)) => {
                            // Ping/Pong or other control frames — keepalive received,
                            // but not a DNS response. Continue waiting.
                        }
                        Err(_) => {
                            // No WebSocket activity for 120s. This catches connections
                            // that are completely silent (no pings, no responses).
                            warn!("DNS proxy: no WebSocket activity for 120s, forcing reconnect ({} pending queries)", pending.len());
                            for (_, pq) in pending.drain() {
                                let _ = pq.tx.send(None);
                            }
                            anyhow::bail!("DNS proxy: WebSocket read timeout (120s)");
                        }
                    }
                }

                // Application-level timeout: check if any pending query has been
                // waiting for a response for more than 10s. The server caps
                // resolution at 5s, so a healthy connection always answers well
                // within this window. Using a persistent interval guarantees this
                // check runs regularly regardless of WebSocket control-frame
                // traffic that would reset a naive sleep.
                _ = check_interval.tick(), if !pending.is_empty() => {
                    let now = Instant::now();
                    let oldest = pending.values().map(|pq| pq.sent_at).min();
                    if let Some(oldest) = oldest {
                        if now.duration_since(oldest) >= Duration::from_secs(10) {
                            warn!("DNS proxy: {} pending queries with no response for 10s, forcing reconnect", pending.len());
                            for (_, pq) in pending.drain() {
                                let _ = pq.tx.send(None);
                            }
                            anyhow::bail!("DNS proxy: pending query timeout (10s)");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Perform X3DH handshake for the DNS WebSocket connection
///
/// Mirrors StreamRelay::perform_handshake but for the DNS endpoint.
async fn dns_handshake(
    reader: &mut WebSocketReader,
    writer: &WebSocketWriter,
    identity_key: &Arc<IdentityKey>,
    server_bundle: &X3DHPublicBundle,
) -> Result<DoubleRatchet> {
    let initiator = X3DHInitiator::from_identity_key(Arc::clone(identity_key));

    let identity_public = initiator.identity_key.x25519_public_key();
    let ephemeral_public = initiator.ephemeral_key.public_key.to_bytes();

    let hello = HandshakeMessage::Hello {
        version: rvpn_core::protocol::ProtocolVersion::CURRENT,
        auth_method: rvpn_core::protocol::AuthMethod::X3DH,
        ephemeral_key: Some(ephemeral_public.to_vec()),
        identity_key: Some(identity_public.to_vec()),
        session_token: None,
        connection_nonce: None,
    };

    let hello_bytes = serde_json::to_vec(&hello).context("Failed to serialize Hello")?;
    writer
        .send(Message::Binary(hello_bytes))
        .await
        .context("Failed to send Hello")?;

    // Bound the wait for ServerHello so a server that accepts the WebSocket
    // but never completes the handshake cannot stall the reconnect loop.
    let response = tokio::time::timeout(Duration::from_secs(15), reader.recv())
        .await
        .map_err(|_| anyhow::anyhow!("DNS handshake: timed out waiting for ServerHello (15s)"))?
        .ok_or_else(|| anyhow::anyhow!("DNS WebSocket closed during handshake"))?;

    match response {
        Message::Binary(data) => {
            let server_hello: HandshakeMessage =
                serde_json::from_slice(&data).context("Failed to parse ServerHello")?;

            match server_hello {
                HandshakeMessage::ServerHello {
                    ephemeral_key: _server_ephemeral,
                    identity_key: server_identity_key,
                    signed_prekey: server_signed_prekey,
                    prekey_signature: server_prekey_signature,
                } => {
                    // Use the SERVER'S ACTUAL wire values for X3DH.
                    //
                    // Previously this discarded every ServerHello key and ran
                    // X3DH against the pre-loaded on-disk bundle. Whenever the
                    // on-disk copy drifted from what the server was actually
                    // running (any `rvpn-server prekey-bundle` regeneration),
                    // chain keys diverged and the first Double Ratchet frame
                    // failed AEAD auth right after a "successful" handshake.
                    //
                    // Mirrors StreamRelay::perform_handshake (commit 8234f819
                    // fixed this for the SOCKS5 path but not the DNS path).
                    let server_identity_key: [u8; 32] = server_identity_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Server identity key has invalid length"))?;
                    let server_signed_prekey: [u8; 32] = server_signed_prekey
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Server signed prekey has invalid length"))?;
                    let prekey_signature_bytes: [u8; 64] = server_prekey_signature
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Prekey signature has invalid length"))?;

                    // Verify the Ed25519 signature on signed_prekey using the
                    // server's wire identity_key. Without this a MITM could
                    // feed us any signed_prekey they liked.
                    let verifying_key = VerifyingKey::from_bytes(&server_identity_key)
                        .map_err(|e| anyhow::anyhow!("Invalid server identity key: {}", e))?;
                    let signature = Signature::from_bytes(&prekey_signature_bytes);
                    verifying_key
                        .verify(&server_signed_prekey, &signature)
                        .map_err(|e| anyhow::anyhow!("Invalid prekey signature: {}", e))?;

                    // identity_x25519_key can't be derived from the Ed25519
                    // public alone; keep the pre-loaded value (it is
                    // deterministic from the same identity).
                    let received_bundle = X3DHPublicBundle {
                        identity_key: server_identity_key,
                        identity_x25519_key: server_bundle.identity_x25519_key,
                        signed_prekey: server_signed_prekey,
                        prekey_signature: prekey_signature_bytes,
                        one_time_prekey: None,
                        identity_key_version: server_bundle.identity_key_version,
                        rotation_signature: server_bundle.rotation_signature,
                    };

                    let (shared_secret, _) = initiator
                        .agree(&received_bundle)
                        .context("X3DH key agreement failed")?;

                    // In X3DH, the server (Bob) doesn't generate an ephemeral key.
                    // We pass zeros since init_alice doesn't use this parameter.
                    Ok(DoubleRatchet::init_alice(shared_secret, [0u8; 32]))
                }
                _ => Err(anyhow::anyhow!("Unexpected handshake message from server")),
            }
        }
        _ => Err(anyhow::anyhow!("Expected binary message during handshake")),
    }
}

/// Parse a DNS wire-format query packet.
///
/// Returns `(transaction_id, domain, qtype)`.
fn parse_dns_query(data: &[u8]) -> Result<(u16, String, u16)> {
    if data.len() < 17 {
        return Err(anyhow::anyhow!("DNS query too short ({} bytes)", data.len()));
    }

    anyhow::ensure!(dns_question(data).is_some(), "Invalid DNS question");
    let txid = u16::from_be_bytes([data[0], data[1]]);

    // Walk the QNAME labels starting at byte 12
    let mut pos = 12usize;
    let mut labels: Vec<&str> = Vec::new();

    loop {
        if pos >= data.len() {
            return Err(anyhow::anyhow!("Truncated DNS QNAME"));
        }
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            return Err(anyhow::anyhow!(
                "DNS pointer compression unsupported in client queries"
            ));
        }
        pos += 1;
        if pos + len > data.len() {
            return Err(anyhow::anyhow!("DNS label extends beyond packet"));
        }
        labels.push(
            std::str::from_utf8(&data[pos..pos + len])
                .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in DNS label"))?,
        );
        pos += len;
    }

    let domain = labels.join(".");

    if pos + 4 > data.len() {
        return Err(anyhow::anyhow!("Truncated DNS QTYPE/QCLASS"));
    }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);

    Ok((txid, domain, qtype))
}

/// Build a DNS wire-format response from a resolved DnsResponse.
///
/// `query` is the original raw wire-format query packet (for extracting the question section).
/// `txid` is the DNS transaction ID (from `parse_dns_query`).
fn build_dns_response(query: &[u8], txid: u16, response: &DnsResponse) -> Vec<u8> {
    // Server has no IPv6 upstream — strip AAAA records to prevent applications
    // from attempting IPv6 connections that will fail with "Network is unreachable".
    let ancount = response.ipv4_addrs.len() as u16;
    let mut out = Vec::with_capacity(64 + 16 * ancount as usize);

    // Header
    out.extend_from_slice(&txid.to_be_bytes());
    // Flags: QR=1 (response), RD=1 (recursion desired, mirrored), RA=1 (available)
    out.extend_from_slice(&[0x81, 0x80]);
    out.extend_from_slice(&[0x00, 0x01]);           // QDCOUNT = 1
    out.extend_from_slice(&ancount.to_be_bytes());  // ANCOUNT
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT=0, ARCOUNT=0

    // Question section: properly parse QNAME length and copy only the question bytes
    // (not the OPT record that may be present in the original query)
    if let Some(question) = dns_question(query) {
        out.extend_from_slice(question);
    }

    // Answer records — pointer 0xC00C refers to QNAME at offset 12
    let ttl = response.ttl.max(30).to_be_bytes();

    for addr in &response.ipv4_addrs {
        out.extend_from_slice(&[0xC0, 0x0C]); // name pointer → offset 12
        out.extend_from_slice(&[0x00, 0x01]); // Type A
        out.extend_from_slice(&[0x00, 0x01]); // Class IN
        out.extend_from_slice(&ttl);
        out.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        out.extend_from_slice(&addr.octets());
    }

    // AAAA records intentionally omitted — server lacks IPv6 connectivity.

    out
}

/// Return the complete, uncompressed question without any trailing EDNS data.
fn dns_question(query: &[u8]) -> Option<&[u8]> {
    if query.get(4..6)? != [0, 1] {
        return None;
    }
    let mut pos = 12;
    loop {
        let len = *query.get(pos)? as usize;
        if len == 0 {
            return query.get(12..pos + 5);
        }
        if len > 63 {
            return None;
        }
        pos += 1 + len;
    }
}

/// Forward local/bypass queries using the explicit UDP/DoH upstream list.
async fn resolve_locally(
    query: &[u8],
    nameservers: &rvpn_split_tunnel::dns_cache::DnsUpstreams,
) -> Result<Vec<u8>> {
    nameservers.query(query).await
}

fn build_dns_nxdomain(query: &[u8], txid: u16) -> Vec<u8> {
    build_dns_error(query, txid, 3)
}

fn build_dns_servfail(query: &[u8], txid: u16) -> Vec<u8> {
    build_dns_error(query, txid, 2)
}

fn build_dns_error(query: &[u8], txid: u16, rcode: u8) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    out[0..2].copy_from_slice(&txid.to_be_bytes());
    out[2] = 0x80 | (query.get(2).copied().unwrap_or_default() & 0x79);
    out[3] = 0x80 | rcode;
    if let Some(question) = dns_question(query) {
        out[5] = 1;
        out.extend_from_slice(question);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_errors_echo_the_question_without_edns() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
        use hickory_proto::rr::{Name, RecordType};

        let mut query = Message::new(42, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A));
        let mut wire = query.to_vec().unwrap();
        wire.extend_from_slice(&[0; 11]);
        for (response, code) in [
            (build_dns_nxdomain(&wire, 42), ResponseCode::NXDomain),
            (build_dns_servfail(&wire, 42), ResponseCode::ServFail),
        ] {
            let parsed = Message::from_vec(&response).unwrap();
            assert_eq!(parsed.metadata.id, 42);
            assert_eq!(parsed.metadata.response_code, code);
            assert!(!parsed.metadata.recursion_desired);
            assert_eq!(parsed.queries, query.queries);
            assert_eq!(response.len(), wire.len() - 11);
        }
        assert_eq!(build_dns_servfail(&wire[..13], 42).len(), 12);
    }

    #[tokio::test]
    async fn listener_survives_closed_udp_peer_and_receives_large_datagrams() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let closed_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let closed_address = closed_peer.local_addr().unwrap();
        drop(closed_peer);
        listener
            .send_to(b"late reply", closed_address)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = vec![42u8; 4096];
        client
            .send_to(&payload, listener.local_addr().unwrap())
            .await
            .unwrap();
        let mut buffer = vec![0u8; 65535];
        let (length, source) = tokio::time::timeout(
            Duration::from_secs(2),
            receive_datagram(&listener, &mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(source, client.local_addr().unwrap());
        assert_eq!(&buffer[..length], payload.as_slice());
    }

    #[tokio::test]
    async fn listener_task_drop_stops_connection_manager() {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stopped_tx, stopped_rx) = oneshot::channel::<()>();
        let manager = WsManagerTask(tokio::spawn(async move {
            let _stopped = stopped_tx;
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        }));
        ready_rx.await.unwrap();
        drop(manager);
        assert!(tokio::time::timeout(Duration::from_secs(2), stopped_rx)
            .await
            .unwrap()
            .is_err());
    }
}
