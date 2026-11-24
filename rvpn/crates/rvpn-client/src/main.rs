// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// R-VPN Client Implementation - Brook-style Architecture
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! R-VPN Client Implementation - Brook-style simplified architecture

mod config;
mod control_panel;
mod dashboard;
mod dns;
mod dns_cache;
mod dns_proxy;
#[cfg(windows)]
mod windows_dns;
#[cfg(any(target_os = "macos", test))]
mod macos_dns;
#[cfg(target_os = "linux")]
mod resolved_dns;
#[cfg(target_os = "linux")]
mod linux_dns;
mod http_proxy;
mod identity_verification;
mod metrics;
mod proxy_common;
mod router;
mod runtime_control;
mod server_pool;
mod server_link;
mod service;
mod socks5;
mod socks5_tunnel;
mod split_tunnel;
mod stats;
mod stream_relay;
// TLS re-exported from rvpn-tls crate
#[cfg(target_os = "linux")]
mod tun;
#[cfg(target_os = "linux")]
mod tun_routes;
#[cfg(target_os = "linux")]
mod tunnel;
mod tunnel_pool;
mod websocket;

// Use mimalloc as the global allocator: glibc malloc arenas retain memory
// indefinitely under this client's allocation churn (a long-running Linux
// install grew to 850 MB RSS in a week; capping MALLOC_ARENA_MAX=2 pinned the
// same workload at ~27 MB, proving arena retention rather than a real leak).
// Disable with --no-default-features to build with the system allocator.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Maximum reconnection attempts before giving up
#[cfg(target_os = "linux")]
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{id as process_id, ExitCode};

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
#[cfg(target_os = "linux")]
use tracing::warn;
use tracing::{error, info};

use config::ClientConfig;
use socks5::Socks5Proxy;

/// Helper to run cleanup on drop
struct OnDrop<F: FnMut()>(F);

impl<F: FnMut()> OnDrop<F> {
    fn new(f: F) -> Self {
        Self(f)
    }
}

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        self.0();
    }
}

/// CLI arguments
#[derive(Parser, Debug)]
#[command(name = "rvpn")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "R-VPN Client - A stealth VPN with Double Ratchet encryption")]
struct Args {
    /// Configuration file (defaults to client.toml beside the executable)
    #[arg(short, long, default_value = "client.toml")]
    config: PathBuf,

    /// Server address (overrides config)
    #[arg(long)]
    server: Option<String>,

    /// Server prekey bundle JSON (relative paths are resolved beside the executable)
    #[arg(long)]
    bundle: Option<PathBuf>,

    /// TLS fingerprint for DPI resistance (chrome, firefox, safari, ios, android, edge, none)
    #[arg(long)]
    fingerprint: Option<String>,

    /// Enable the web control panel and set its listen address (e.g. 127.0.0.1:9800)
    #[arg(long)]
    dashboard_listen: Option<String>,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Subcommands
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Import a public rVPN deployment link
    Import {
        link: String,
        #[arg(long)]
        replace_primary: bool,
    },
    /// Install or manage the system service (requires administrator/root)
    Service {
        #[command(subcommand)]
        action: service::ServiceAction,
    },
    /// Generate new identity key
    Keygen {
        /// Key type (ed25519)
        #[arg(long, default_value = "ed25519")]
        key_type: String,
        /// Output file path
        #[arg(short, long, default_value = "identity.key")]
        output: PathBuf,
    },
    /// Extract public key from identity file
    Pubkey {
        /// Input identity key file
        #[arg(short, long)]
        key: PathBuf,
        /// Output public key file
        #[arg(short, long, default_value = "public.key")]
        output: PathBuf,
    },
    /// Show VPN status
    Status {
        /// Number of historical entries to show
        #[arg(short, long, default_value_t = 5)]
        entries: usize,
    },
}

fn main() -> Result<ExitCode> {
    let mut args = Args::parse();
    // Relative CLI input paths are anchored to the executable, independently
    // of the shell or service manager's working directory on all platforms.
    let executable = std::env::current_exe().context("Failed to locate client executable")?;
    let executable_dir = executable.parent().context("Executable has no parent directory")?;
    args.config = config::resolve_path(&args.config, executable_dir);
    if let Some(bundle) = &mut args.bundle {
        *bundle = config::resolve_path(bundle, executable_dir);
    }
    if let Some(Commands::Import { link, replace_primary }) = &args.command {
        server_link::import(&args.config, link, *replace_primary)?;
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(Commands::Service { action }) = &args.command {
        anyhow::ensure!(
            args.server.is_none()
                && args.bundle.is_none()
                && args.fingerprint.is_none()
                && args.dashboard_listen.is_none()
                && args.verbose == 0,
            "Service settings must be saved in the config file; CLI overrides are not persisted"
        );
        service::execute(action, &args.config)?;
        return Ok(ExitCode::SUCCESS);
    }
    match tokio::runtime::Runtime::new()?.block_on(async_main(args)) {
        Ok(status) => Ok(status),
        Err(error) => {
            eprintln!("Client terminated: {error:#}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn check_format(path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(path.extension().and_then(|ext| ext.to_str()), Some("toml" | "json")),
        "Configuration file must have a .toml or .json extension: {}",
        path.display()
    );
    Ok(())
}

fn create_initial_config(path: &Path) -> anyhow::Result<()> {
    use std::io::{ErrorKind, Write};

    let directory = path.parent().context("Configuration path has no parent directory")?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    let contents = if path.extension().is_some_and(|ext| ext == "json") {
        "{\"dashboard\":{\"enabled\":true}}\n"
    } else {
        "[dashboard]\nenabled = true\n"
    };
    file.write_all(contents.as_bytes())?;
    file.as_file().sync_all()?;
    match file.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Failed to create {}", path.display())),
    }
}

async fn async_main(args: Args) -> Result<ExitCode> {
    let starting_client = args.command.is_none();
    let exists = args.config.try_exists()?;
    if starting_client {
        check_format(&args.config)?;
        if !exists {
            create_initial_config(&args.config)?;
        }
    }
    let mut startup_problem = None;
    let config = if exists || starting_client {
        match ClientConfig::load(&args.config) {
            Ok(config) => config,
            Err(_) if starting_client => {
                // The repair draft can safely replace unreadable syntax or field types
                // only if we can read the original bytes for revision checks and rollback.
                std::fs::read(&args.config)
                    .with_context(|| format!("Failed to read {}", args.config.display()))?;
                startup_problem = Some("配置文件无法解析，请在 WebUI 中修正或导入服务器链接。".into());
                let mut config = control_panel::setup_config();
                let directory = args.config.parent().context("Configuration path has no parent directory")?;
                config.resolve_paths(directory);
                config
            }
            Err(error) => {
                return Err(error).with_context(|| format!("Invalid client configuration: {}", args.config.display()));
            }
        }
    } else {
        ClientConfig::default()
    };
    #[cfg(target_os = "macos")]
    if starting_client && startup_problem.is_none() {
        service::authorize_foreground(&config);
    }
    let logging = match rvpn_logging::init_client_startup(&config.logging, args.verbose, "rvpn-client") {
        Ok(logging) => logging,
        Err(error) if starting_client => {
            startup_problem = Some(format!("日志配置无效：{error:#}"));
            rvpn_logging::init_client_startup(&Default::default(), args.verbose, "rvpn-client")?
        }
        Err(error) => return Err(error),
    };
    let result = run_client(args, config, startup_problem, &logging).await;
    if let Err(error) = &result {
        let _ = service::report_startup(None, Some(format!("{error:#}")), None);
    }
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) if logging.writes_to_file() => {
            error!("Client terminated: {error:#}");
            Ok(ExitCode::FAILURE)
        }
        Err(error) => Err(error),
    }
}

async fn run_client(
    args: Args,
    config: ClientConfig,
    startup_problem: Option<String>,
    logging: &rvpn_logging::ReloadableLogging,
) -> Result<()> {
    info!("R-VPN Client v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    if args.config.exists() {
        info!("Loading configuration from {:?}", args.config);
    } else {
        info!("No config file found, using defaults");
    }

    // Override with CLI arguments
    let overrides = runtime_control::Overrides {
        server: args.server.clone(),
        bundle: args.bundle.clone(),
        fingerprint: args.fingerprint.clone(),
        dashboard_listen: args.dashboard_listen.clone(),
    };
    let mut config = config;
    overrides.apply(&mut config);

    // Handle subcommands
    match args.command {
        Some(Commands::Keygen { output, .. }) => {
            return keygen(output);
        }
        Some(Commands::Pubkey { key, output }) => {
            return pubkey(key, output);
        }
        Some(Commands::Status { entries }) => {
            return show_status(entries).await;
        }
        _ => {}
    }

    runtime_control::run(config, args.config, overrides, startup_problem, logging).await
}

/// Run in SOCKS5 proxy mode (Brook-style)
async fn run_socks5(
    config: ClientConfig,
    ready: tokio::sync::oneshot::Sender<Option<String>>,
    allow_dns_failure: bool,
) -> Result<()> {
    info!("Starting R-VPN Client in SOCKS5 mode (Brook-style)");
    info!("Server: {}", config.server_address);

    // Save PID file
    let pid_file = config.data_dir.join("rvpn.pid");
    tokio::fs::create_dir_all(&config.data_dir).await?;
    tokio::fs::write(&pid_file, process_id().to_string()).await?;
    info!("Saved PID to {:?}", pid_file);

    // Set up cleanup on exit
    let pid_file_clone = pid_file.clone();
    let _guard = OnDrop::new(move || {
        let _ = std::fs::remove_file(&pid_file_clone);
    });

    let socks_addr: SocketAddr = config.socks5.listen_address.parse()?;

    // Initialize stats manager for historical tracking
    let stats_manager = stats::init_global_stats_manager_with_dir(config.data_dir.clone()).await;
    let _stats_handle = stats_manager.start_collection();

    // Create SOCKS5 proxy (each connection manages its own WebSocket)
    let proxy = Socks5Proxy::new(socks_addr, &config).await?;
    // Bind every listener before reporting readiness, so a failed reload can
    // restore the previous generation instead of silently losing a proxy.
    let socks_listener = tokio::net::TcpListener::bind(socks_addr).await
        .with_context(|| format!("Failed to bind SOCKS5 proxy to {socks_addr}"))?;

    // Optionally start HTTP proxy (shares mux tunnel with SOCKS5)
    if config.http_proxy.enabled {
        let http_listen: SocketAddr = config.http_proxy.listen_address.parse().with_context(|| {
            format!(
                "Invalid HTTP proxy listen address: {}",
                config.http_proxy.listen_address
            )
        })?;

        let http_proxy = http_proxy::HttpProxy::new(
            http_listen,
            &config,
            proxy.identity_key(),
            proxy.server_bundle(),
            proxy.split_tunnel(),
            proxy.dns_resolver(),
            proxy.mux_tunnel(),
            proxy.tunnel_pools(),
            proxy.pool(),
            proxy.router(),
        )
        .await?;

        let listener = tokio::net::TcpListener::bind(http_listen).await
            .with_context(|| format!("Failed to bind HTTP proxy to {http_listen}"))?;

        tokio::spawn(async move {
            if let Err(e) = http_proxy.run_with_listener(listener).await {
                error!("HTTP proxy fatal error: {}", e);
            }
        });
    }

    let mut dns_warning = None;
    let (_system_dns, dns) = if config.dns_proxy.enabled {
        let start_dns = async {
            let takeover = config.dns_proxy.takes_over_system_dns();
            #[cfg(target_os = "macos")]
            anyhow::ensure!(!takeover || unsafe { libc::geteuid() } == 0,
                "macOS 系统 DNS 接管需要管理员权限。请从终端重新运行 ./rvpn 并授权，或关闭接管并使用高位 DNS 端口");

            let (dns, primary, secondary) = bind_dns_proxy(&config, &proxy).await?;
            #[cfg(windows)]
            let system_dns = takeover.then(windows_dns::SystemDns::take_over).transpose()?;
            #[cfg(target_os = "macos")]
            let system_dns = takeover.then(macos_dns::SystemDns::take_over).transpose()?;
            #[cfg(target_os = "linux")]
            let system_dns = if takeover {
                linux_dns::SystemDns::install(config.dns_proxy.effective_listener().parse()?, true)?
            } else {
                None
            };
            #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
            let system_dns: Option<()> = { let _ = takeover; None };
            Ok::<_, anyhow::Error>((system_dns, Some(tokio::spawn(dns.run_with_sockets(primary, secondary)))))
        };
        match start_dns.await {
            Ok(active) => active,
            Err(error) if allow_dns_failure => {
                dns_warning = Some(format!("DNS 未启动，代理已启动。{error:#}"));
                (None, None)
            }
            Err(error) => return Err(error),
        }
    } else {
        (None, None)
    };
    let _ = ready.send(dns_warning);
    tokio::select! {
        result = proxy.run_with_listener(socks_listener) => result,
        result = async {
            match dns {
                Some(task) => task.await.context("DNS proxy task stopped")?,
                None => std::future::pending().await,
            }
        } => result,
    }
}

/// Check delivery to each bound socket before changing any adapter. Peeking
/// preserves DNS requests that arrived before our empty probe datagram.
async fn check_dns_loopback(listener: &tokio::net::UdpSocket) -> Result<()> {
    let address = listener.local_addr()?;
    let probe = tokio::net::UdpSocket::bind(SocketAddr::new(address.ip(), 0)).await?;
    probe.send_to(&[], address).await?;
    let mut packet = vec![0; 65535];
    tokio::time::timeout(std::time::Duration::from_secs(2), listener.peek_from(&mut packet))
        .await.with_context(|| format!("DNS 回环监听 {address} 未收到探测数据"))??;
    Ok(())
}

async fn bind_dns_proxy(
    config: &ClientConfig,
    proxy: &Socks5Proxy,
) -> Result<(std::sync::Arc<dns_proxy::DnsProxy>, tokio::net::UdpSocket, Option<tokio::net::UdpSocket>)> {
    let address: SocketAddr = config.dns_proxy.effective_listener().parse()?;
    let nameservers = rvpn_split_tunnel::dns_cache::DnsUpstreams::new(&config.dns_proxy.nameservers)?;
    nameservers.validate_listener(address)?;
    let extra_hosts = config.extra_servers.iter().map(|server| parse_server_url(&server.address).0).collect();
    let doh_hosts = config.dns_proxy.nameservers.iter()
        .filter_map(|endpoint| rvpn_split_tunnel::dns_cache::doh_upstream_hostname(endpoint)).collect();
    let dns = std::sync::Arc::new(dns_proxy::DnsProxy::new(
        address, proxy.server_host().to_string(), proxy.server_port(), proxy.server_path(),
        proxy.tls_fingerprint(), proxy.identity_key(), proxy.server_bundle(), proxy.split_tunnel(),
        proxy.dns_resolver(), nameservers, extra_hosts, doh_hosts, config.dns_proxy.host_records()?,
    ));
    let socket = bind_dns_listener(address).await?;
    let secondary = if config.dns_proxy.takes_over_system_dns() {
        let address = config::DnsProxyConfig::SYSTEM_DNS_V6.parse()?;
        let secondary = bind_dns_listener(address).await?;
        tokio::try_join!(check_dns_loopback(&socket), check_dns_loopback(&secondary))?;
        Some(secondary)
    } else { None };
    Ok((dns, socket, secondary))
}

async fn bind_dns_listener(address: SocketAddr) -> Result<tokio::net::UdpSocket> {
    tokio::net::UdpSocket::bind(address).await.map_err(|error| {
        let detail = match error.kind() {
            std::io::ErrorKind::AddrInUse => "端口已占用",
            std::io::ErrorKind::PermissionDenied => "权限不足",
            _ => "无法绑定",
        };
        anyhow::Error::new(error).context(format!("DNS UDP 监听 {address} 失败，{detail}"))
    })
}

#[cfg(not(target_os = "linux"))]
async fn run_tun(_: ClientConfig, _: tokio::sync::oneshot::Sender<Option<String>>) -> Result<()> {
    anyhow::bail!("Managed desktop TUN routing and DNS currently require Linux")
}

#[cfg(target_os = "linux")]
async fn run_tun(mut config: ClientConfig, ready: tokio::sync::oneshot::Sender<Option<String>>) -> Result<()> {
    use std::sync::Arc;
    use tun::TunDevice;
    use tunnel::VpnTunnel;

    anyhow::ensure!(config.extra_servers.is_empty() && config.routing.is_empty(),
        "Multi-server routing is supported only in proxy mode");
    anyhow::ensure!(config.dns_proxy.enabled, "TUN requires the local DNS proxy for domain rules");
    if config.dns_proxy.nameservers.is_empty() {
        config.dns_proxy.nameservers.clone_from(&config.tun.dns_servers);
    }
    websocket::configure_endpoint_dns(&config)?;
    let listen: SocketAddr = config.dns_proxy.effective_listener().parse()?;
    anyhow::ensure!(listen.is_ipv4() && listen.ip().is_loopback() && listen.port() == 53,
        "TUN DNS proxy must listen on an IPv4 loopback address at port 53");

    let engine = Socks5Proxy::new(listen, &config).await?;
    let split = engine.split_tunnel();
    let dns_resolver = engine.dns_resolver();
    let (host, port, path) = parse_server_url(&config.server_address);
    let path = path.trim_end_matches('/');
    let tun_path = if path.ends_with("/tun") { path.to_owned() } else { format!("{path}/tun") };
    let mut upstream_ips = Vec::new();
    for upstream in &config.dns_proxy.nameservers {
        if upstream.starts_with("https://") {
            let url = url::Url::parse(upstream)?;
            let hostname = url.host_str().context("Missing DoH host")?.trim_matches(['[', ']']);
            upstream_ips.extend(dns_resolver.resolve(hostname, url.port().unwrap_or(443)).await?.into_iter().map(|addr| addr.ip()));
        } else if let Ok(address) = upstream.parse::<SocketAddr>() {
            upstream_ips.push(address.ip());
        } else {
            upstream_ips.push(upstream.parse()?);
        }
    }

    let (dns, socket, secondary) = bind_dns_proxy(&config, &engine).await?;
    dns.prepare_for_tun();
    let connection = async {
        let resumption = rvpn_tls::ResumptionStore::new();
        let mut ready = Some(ready);
        let mut failures = 0;
        loop {
            let session = async {
                // Connect before capturing system routes. Record all IPs used to reach
                // the TLS frontend, including ECH alternative addresses.
                let tunnel = VpnTunnel::connect(&host, port, &tun_path, config.tls_fingerprint,
                    config.sni_hostname.as_deref(), &config.identity_key_file, config.prekey_bundle.as_deref(),
                    &config.server_identity, Some(&resumption)).await?;
                let (virtual_ip, server_mtu) = {
                    let guard = tunnel.read().await;
                    let address = guard.virtual_ip.context("TUN server did not assign an IPv4 address")?;
                    info!(%address, gateway = ?guard.gateway_ip, mtu = guard.mtu, "TUN address assigned");
                    (address, guard.mtu)
                };
                let mut tun_config = config.tun.clone();
                tun_config.mtu = tun_config.mtu.min(server_mtu);
                let device = TunDevice::create_with_ip(&tun_config, &format!("{virtual_ip}/32"))?;
                let (direct, forced, full_unknown) = split.ipv4_routes().await;
                let mut routes = tun_routes::Routes::new(&device.name()?, &tun_config.routes, direct, forced, full_unknown)?;
                for address in split.server_ipv4_exceptions().await.into_iter().chain(upstream_ips.iter().copied()) {
                    routes.pin(address)?;
                }
                routes.activate()?;
                let routes = Arc::new(routes);
                let weak = Arc::downgrade(&routes);
                websocket::set_endpoint_route_hook(Some(Arc::new(move |address| {
                    if let Some(routes) = weak.upgrade() { routes.pin(address)?; }
                    Ok(())
                })));
                let _hook = OnDrop::new(|| websocket::set_endpoint_route_hook(None));
                dns.set_tun_routes(&routes);
                let _dns = linux_dns::SystemDns::install(listen, config.dns_proxy.takes_over_system_dns())?;
                dashboard::TUN_READY.store(true, std::sync::atomic::Ordering::Relaxed);
                let _status = OnDrop::new(|| dashboard::TUN_READY.store(false, std::sync::atomic::Ordering::Relaxed));
                failures = 0;
                if let Some(ready) = ready.take() {
                    let _ = ready.send(None);
                }
                let (_shutdown, shutdown) = tokio::sync::watch::channel(false);
                tokio::select! {
                    result = device.run(tunnel, shutdown) => result,
                    result = routes.expire() => result.context("TUN DNS route expiry failed"),
                }
            }.await;
            if ready.is_some() {
                return session.context("TUN initialization failed");
            }
            failures += 1;
            if failures >= MAX_RECONNECT_ATTEMPTS {
                return session.and_then(|_| Err(anyhow::anyhow!("TUN network stopped")));
            }
            warn!(?session, "TUN disconnected, retrying with system routes restored");
            dashboard::record_reconnect();
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    };
    tokio::select! {
        result = connection => result,
        result = Arc::clone(&dns).run_with_sockets(socket, secondary) => result.context("TUN DNS listener stopped"),
    }
}

/// Handle shutdown signals (SIGINT, SIGTERM on Unix; Ctrl+C on Windows)
async fn handle_signals(shutdown_tx: tokio::sync::watch::Sender<bool>) {
    #[cfg(unix)]
    {
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("Failed to create SIGINT handler");
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to create SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown...");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown...");
            }
        }
    }

    #[cfg(windows)]
    {
        if service::windows::is_service() {
            service::windows::wait_stop().await;
        } else {
            tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        }
        info!("Received shutdown request, initiating graceful shutdown...");
    }

    let _ = shutdown_tx.send(true);
}

/// Wait for shutdown signal to be received


/// Parse server URL into (host, port, path) components
fn parse_server_url(url: &str) -> (String, u16, String) {
    // Handle ws:// and wss:// URLs
    let url = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url);

    // Split path
    let (host_port, path) = url
        .split_once('/')
        .map(|(hp, p)| (hp, format!("/{}", p)))
        .unwrap_or((url, "/".to_string()));

    // Handle IPv6: [host]:port
    if host_port.starts_with('[') {
        if let Some(bracket_end) = host_port.find(']') {
            let host = host_port[1..bracket_end].to_string();
            let port = if bracket_end + 1 < host_port.len() && host_port.as_bytes()[bracket_end + 1] == b':' {
                host_port[bracket_end + 2..].parse().unwrap_or(443)
            } else {
                443
            };
            return (host, port, path);
        }
    }

    // IPv4 or hostname
    let (host, port) = host_port
        .split_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(443)))
        .unwrap_or_else(|| (host_port.to_string(), 443));

    (host, port, path)
}

/// Generate a new identity key
fn keygen(output: PathBuf) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use rvpn_core::crypto::IdentityKey;

    let identity = IdentityKey::generate();

    // Create a simple key file format
    let key_data = format!(
        "R-VPN-IDENTITY-v1\n{}\n{}\n",
        BASE64.encode(identity.verifying_key.as_bytes()),
        BASE64.encode(identity.signing_key.to_bytes())
    );

    // Write with restrictive permissions (owner read/write only) on Unix
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&output)?
            .write_all(key_data.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&output, key_data)?;
    }

    info!("Generated identity key: {:?}", output);
    info!("Client public identity (Ed25519, base64): {}", BASE64.encode(identity.verifying_key.to_bytes()));
    info!("Client identity fingerprint: {}", rvpn_core::identity_pin::encode_identity_pin(identity.verifying_key.as_bytes())?);

    Ok(())
}

/// Extract public key from identity file
fn pubkey(key_path: PathBuf, output: PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(&key_path)?;
    let lines: Vec<&str> = content.lines().collect();

    if lines.len() < 3 || lines[0] != "R-VPN-IDENTITY-v1" {
        anyhow::bail!("Invalid key file format");
    }

    let public_key_b64 = lines[1];

    // Write public key file
    let key_data = format!("R-VPN-PUBLICKEY-v1\n{}\n", public_key_b64);
    std::fs::write(&output, key_data)?;
    info!("Extracted public key to: {:?}", output);

    Ok(())
}

/// Show connection status
async fn show_status(entries: usize) -> Result<()> {
    use crate::stats::StatsHistory;

    // Get data directory
    let data_dir = dirs::data_dir()
        .map(|d| d.join("rvpn"))
        .unwrap_or_else(|| PathBuf::from("."));

    // Check if client is running
    let pid_file = data_dir.join("rvpn.pid");
    let is_running = if pid_file.exists() {
        let pid_str = std::fs::read_to_string(&pid_file)?;
        let pid: u32 = pid_str.trim().parse()?;
        #[cfg(unix)]
        {
            // On Unix, signal 0 doesn't send anything but checks if process exists
            std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        #[cfg(windows)]
        {
            std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/NH"])
                .output()
                .map(|o| {
                    let output = String::from_utf8_lossy(&o.stdout);
                    output.contains(&pid.to_string())
                })
                .unwrap_or(false)
        }
    } else {
        false
    };

    // Print status header
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    R-VPN Client Status                      ║");
    println!("╠══════════════════════════════════════════════════════════════╣");

    if is_running {
        println!(
            "║  Status: \x1b[32mRunning\x1b[0m                                              ║"
        );
        if pid_file.exists() {
            if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
                println!(
                    "║  PID: {}                                                 ║",
                    pid_str.trim()
                );
            }
        }
    } else {
        println!("║  Status: \x1b[31mStopped\x1b[0m                                             ║");
    }

    // Load and display historical stats
    match StatsHistory::load_from(&data_dir).await {
        Ok(history) => {
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!(
                "║  Historical Stats ({:.0} entries)                               ║",
                history.len()
            );
            println!("╠══════════════════════════════════════════════════════════════╣");

            if let Some(latest) = history.latest() {
                let snapshot = &latest.snapshot;
                println!(
                    "║  Last Update: {}                                   ║",
                    latest.formatted_time()
                );
                println!(
                    "║  Connection Uptime: {}                              ║",
                    format_uptime(snapshot.connection_uptime_secs)
                );
                println!(
                    "║  Messages Sent: {}                                 ║",
                    format_number(snapshot.messages_sent_total)
                );
                println!(
                    "║  Messages Received: {}                             ║",
                    format_number(snapshot.messages_received_total)
                );
                println!(
                    "║  Data Sent: {}                                      ║",
                    format_bytes(snapshot.bytes_sent_total)
                );
                println!(
                    "║  Data Received: {}                                  ║",
                    format_bytes(snapshot.bytes_received_total)
                );
            } else {
                println!("║  No historical data available                              ║");
            }

            // Show recent entries if requested
            if entries > 0 && history.len() > 1 {
                println!("╠══════════════════════════════════════════════════════════════╣");
                println!(
                    "║  Recent Entries (last {})                                ║",
                    entries
                );
                println!("╠══════════════════════════════════════════════════════════════╣");

                let history_vec: Vec<_> = history.entries().iter().rev().take(entries).collect();
                for entry in history_vec {
                    println!(
                        "║  {} - {:.1} msg/s                           ║",
                        entry.formatted_time(),
                        entry.snapshot.messages_received_per_sec
                    );
                }
            }
        }
        Err(e) => {
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!(
                "║  Error loading stats: {}                                  ║",
                e
            );
        }
    }

    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}

/// Format uptime
fn format_uptime(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

/// Format number with commas
fn format_number(n: u64) -> String {
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap_or_default()
        .join(",")
}

/// Format bytes
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    format!("{:.2} {}", size, UNITS[unit_idx])
}
