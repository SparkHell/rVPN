// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP/HTTPS Proxy Server
//!
//! Handles two request types:
//! - **HTTP CONNECT**: `CONNECT host:port HTTP/1.1` — tunnels HTTPS traffic
//! - **Plain HTTP**: `GET http://host/path HTTP/1.1` — forwards HTTP requests
//!
//! Compatible with `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` environment variables.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use crate::server_pool::parse_server_url;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use rvpn_core::crypto::{IdentityKey, X3DHPublicBundle};

use crate::config::{ClientConfig, HttpProxyConfig, ServerIdentityConfig, Socks5Mode};
use crate::proxy_common::{self, ProxyHandle};
use crate::router::Router;
use crate::server_pool::ServerPool;
use crate::split_tunnel::SplitTunnel;
use rvpn_tls::TlsFingerprint;
use crate::socks5_tunnel::Socks5Tunnel;
use crate::dns_cache::DnsResolver;
use crate::tunnel_pool::TunnelPools;

/// HTTP/HTTPS Proxy server
pub struct HttpProxy {
    listen_addr: SocketAddr,
    server_host: String,
    server_port: u16,
    server_path: String,
    tls_fingerprint: TlsFingerprint,
    sni_hostname: Option<String>,
    identity_key: Arc<IdentityKey>,
    server_bundle: Arc<X3DHPublicBundle>,
    server_identity: ServerIdentityConfig,
    split_tunnel: Arc<SplitTunnel>,
    http_config: HttpProxyConfig,
    mux_tunnel: Arc<Mutex<Option<Arc<Socks5Tunnel>>>>,
    tunnel_pools: Option<Arc<TunnelPools>>,
    mode: Socks5Mode,
    pool: Arc<ServerPool>,
    router: Arc<Router>,
}

impl HttpProxy {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        listen_addr: SocketAddr,
        config: &ClientConfig,
        identity_key: Arc<IdentityKey>,
        server_bundle: Arc<X3DHPublicBundle>,
        split_tunnel: Arc<SplitTunnel>,
        dns_resolver: Arc<DnsResolver>,
        mux_tunnel: Arc<Mutex<Option<Arc<Socks5Tunnel>>>>,
        tunnel_pools: Option<Arc<TunnelPools>>,
        pool: Arc<ServerPool>,
        router: Arc<Router>,
    ) -> Result<Self> {
        let (host, port, path) = parse_server_url(&config.server_address);

        dns_resolver.start_cleanup_task();

        // The compatibility flag selects a single pipe only for a single exit.
        let mode = if config.http_proxy.multiplex && pool.extra_count() == 0 {
            Socks5Mode::Multiplex
        } else {
            config.socks5.effective_mode()
        };

        Ok(Self {
            listen_addr,
            server_host: host,
            server_port: port,
            server_path: path,
            tls_fingerprint: config.tls_fingerprint,
            sni_hostname: config.sni_hostname.clone(),
            identity_key,
            server_bundle,
            server_identity: config.server_identity.clone(),
            split_tunnel,
            http_config: config.http_proxy.clone(),
            mux_tunnel,
            tunnel_pools,
            mode,
            pool,
            router,
        })
    }

    #[allow(dead_code)] // Library entry point; the CLI supplies a bound listener.
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .with_context(|| format!("Failed to bind HTTP proxy to {}", self.listen_addr))?;

        self.run_with_listener(listener).await
    }

    pub(crate) async fn run_with_listener(&self, listener: TcpListener) -> Result<()> {

        info!("HTTP proxy listening on {}", self.listen_addr);

        loop {
            let (socket, addr) = listener.accept().await?;

            // Detect silently-dead peers (roaming phones, NAT rebinds) so the
            // flow built on this socket cannot be pinned forever.
            let socket = match proxy_common::enable_tcp_keepalive(socket) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to set TCP keepalive for {}: {}", addr, e);
                    continue;
                }
            };

            let proxy = ProxyHandle {
                server_host: self.server_host.clone(),
                server_port: self.server_port,
                server_path: self.server_path.clone(),
                tls_fingerprint: self.tls_fingerprint,
                sni_hostname: self.sni_hostname.clone(),
                identity_key: Arc::clone(&self.identity_key),
                server_bundle: Arc::clone(&self.server_bundle),
                server_identity: self.server_identity.clone(),
                split_tunnel: Arc::clone(&self.split_tunnel),
                mode: self.mode,
                mux_path: self.http_config.mux_path.clone(),
                mux_tunnel: self.mux_tunnel.clone(),
                tunnel_pools: self.tunnel_pools.clone(),
                pool: Arc::clone(&self.pool),
                router: Arc::clone(&self.router),
            };

            let auth_config = if self.http_config.auth_enabled {
                Some(AuthConfig {
                    username: self
                        .http_config
                        .auth_username
                        .clone()
                        .unwrap_or_default(),
                    password: self
                        .http_config
                        .auth_password
                        .clone()
                        .unwrap_or_default(),
                })
            } else {
                None
            };

            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, addr, proxy, auth_config).await {
                    warn!("HTTP connection error from {}: {:#}", addr, e);
                }
            });
        }
    }
}

struct AuthConfig {
    username: String,
    password: String,
}

type Body = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, hyper::Error>;

fn response(status: hyper::StatusCode) -> hyper::Response<Body> {
    use http_body_util::BodyExt;
    let mut response = hyper::Response::new(
        http_body_util::Empty::new()
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}

async fn handle_connection(
    socket: TcpStream,
    addr: SocketAddr,
    proxy: ProxyHandle,
    auth: Option<AuthConfig>,
) -> Result<()> {
    use hyper_util::rt::{TokioIo, TokioTimer};
    let service = hyper::service::service_fn(|request| async {
        let reply = match forward(request, &proxy, auth.as_ref()).await {
            Ok(reply) => reply,
            Err(e) => {
                warn!("HTTP proxy request from {addr} failed: {e:#}");
                use std::io::ErrorKind;
                let status = match e.downcast_ref::<std::io::Error>().map(|e| e.kind()) {
                    Some(ErrorKind::PermissionDenied) => hyper::StatusCode::FORBIDDEN,
                    Some(ErrorKind::TimedOut) => hyper::StatusCode::GATEWAY_TIMEOUT,
                    _ => hyper::StatusCode::BAD_GATEWAY,
                };
                response(status)
            }
        };
        Ok::<_, std::convert::Infallible>(reply)
    });
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(30))
        .max_buf_size(64 * 1024)
        .serve_connection(TokioIo::new(socket), service)
        .with_upgrades()
        .await?;
    Ok(())
}

fn supported_framing(headers: &hyper::HeaderMap) -> bool {
    let mut codings = headers.get_all("transfer-encoding").iter();
    match codings.next() {
        None => true,
        Some(coding) => {
            coding.as_bytes().eq_ignore_ascii_case(b"chunked")
                && codings.next().is_none()
                && !headers.contains_key("content-length")
        }
    }
}

fn strip_hop_headers(headers: &mut hyper::HeaderMap) {
    let names: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|s| hyper::header::HeaderName::from_bytes(s.trim().as_bytes()).ok())
        .collect();
    for name in names {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "transfer-encoding",
    ] {
        headers.remove(name);
    }
}

async fn forward(
    mut request: hyper::Request<hyper::body::Incoming>,
    proxy: &ProxyHandle,
    auth: Option<&AuthConfig>,
) -> Result<hyper::Response<Body>> {
    use http_body_util::BodyExt;
    use hyper::{Method, StatusCode};
    use hyper_util::rt::TokioIo;
    if let Some(auth) = auth {
        let value = request
            .headers()
            .get("proxy-authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if auth.username.is_empty()
            || auth.password.is_empty()
            || !check_basic_auth(value, &auth.username, &auth.password)
        {
            let mut reply = response(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
            reply
                .headers_mut()
                .insert("proxy-authenticate", "Basic realm=\"rvpn\"".parse()?);
            return Ok(reply);
        }
    }
    let connect = request.method() == Method::CONNECT;
    let uri = request.uri();
    if uri.scheme_str().is_some_and(|scheme| scheme != "http") {
        return Ok(response(StatusCode::BAD_REQUEST));
    }
    let authority = uri.authority().cloned().or_else(|| {
        if connect {
            return None;
        }
        request.headers().get("host")?.to_str().ok()?.parse().ok()
    });
    let Some(authority) = authority else {
        return Ok(response(StatusCode::BAD_REQUEST));
    };
    if authority.as_str().contains('@') || authority.host().is_empty() {
        return Ok(response(StatusCode::BAD_REQUEST));
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = match authority.port_u16() {
        Some(port) => port,
        None if authority.as_str() == authority.host() => {
            if connect {
                443
            } else {
                80
            }
        }
        None => return Ok(response(StatusCode::BAD_REQUEST)),
    };
    if !supported_framing(request.headers())
        || (connect
            && (request.headers().contains_key("transfer-encoding")
                || request
                    .headers()
                    .get("content-length")
                    .is_some_and(|v| v != "0")))
    {
        return Ok(response(StatusCode::BAD_REQUEST));
    }
    let mut remote = proxy_common::open_target(host, port, proxy).await?;
    if connect {
        let upgrade = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            if let Ok(stream) = upgrade.await {
                if let Err(e) =
                    tokio::io::copy_bidirectional(&mut TokioIo::new(stream), &mut remote).await
                {
                    debug!("CONNECT relay ended: {e}");
                }
            }
        });
        return Ok(response(StatusCode::OK));
    }
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    *request.uri_mut() = path.parse()?;
    strip_hop_headers(request.headers_mut());
    request
        .headers_mut()
        .insert("host", authority.as_str().parse()?);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(64 * 1024)
        .handshake(TokioIo::new(remote))
        .await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("Upstream HTTP connection ended: {e}");
        }
    });
    let mut reply = sender.send_request(request).await?;
    if !supported_framing(reply.headers()) {
        return Ok(response(StatusCode::BAD_GATEWAY));
    }
    strip_hop_headers(reply.headers_mut());
    Ok(reply.map(|body| body.boxed_unsync()))
}

fn check_basic_auth(header_value: &str, expected_user: &str, expected_pass: &str) -> bool {
    let Some((scheme, encoded)) = header_value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }
    let decoded = match BASE64.decode(encoded) {
        Ok(d) => d,
        Err(_) => return false,
    };

    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let (user, pass) = match decoded_str.split_once(':') {
        Some((u, p)) => (u, p),
        None => return false,
    };

    use subtle::ConstantTimeEq;
    let user_ok: bool = ConstantTimeEq::ct_eq(user.as_bytes(), expected_user.as_bytes()).into();
    let pass_ok: bool = ConstantTimeEq::ct_eq(pass.as_bytes(), expected_pass.as_bytes()).into();

    user_ok && pass_ok
}
