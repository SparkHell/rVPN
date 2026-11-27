//! The panel lives on the process runtime; every VPN generation owns a separate
//! runtime. Dropping that runtime cancels all nested relay/DNS/pool tasks before
//! listeners are reused, including tasks spawned by library components.
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{id as process_id, ExitCode},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info};
#[cfg(target_os = "linux")]
use tracing::warn;

use crate::{
    config::ClientConfig,
    control_panel::{ApplyRequest, ControlPanel},
    dashboard,
    server_pool::parse_server_url,
    service,
    socks5::Socks5Proxy,
};

/// CLI arguments
#[derive(Parser, Debug)]
#[command(name = "rvpn")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "R-VPN Client - A stealth VPN with Double Ratchet encryption")]
pub struct Args {
    /// Configuration file (defaults to client.toml beside the executable)
    #[arg(short, long, default_value = "client.toml")]
    pub config: PathBuf,

    /// Server address (overrides config)
    #[arg(long)]
    pub server: Option<String>,

    /// Server prekey bundle JSON (relative paths are resolved beside the executable)
    #[arg(long)]
    pub bundle: Option<PathBuf>,

    /// TLS fingerprint for DPI resistance (chrome, firefox, safari, ios, android, edge, none)
    #[arg(long)]
    pub fingerprint: Option<String>,

    /// Enable the web control panel and set its listen address (e.g. 127.0.0.1:9800)
    #[arg(long)]
    pub dashboard_listen: Option<String>,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Subcommands
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Subcommands
#[derive(Subcommand, Debug)]
pub enum Commands {
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

#[cfg(target_os = "linux")]
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

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

#[derive(Clone, Default)]
pub struct Overrides {
    pub server: Option<String>,
    pub bundle: Option<PathBuf>,
    pub fingerprint: Option<String>,
    pub dashboard_listen: Option<String>,
}

impl Overrides {
    pub fn apply(&self, config: &mut ClientConfig) {
        if let Some(server) = &self.server {
            config.server_address = server.clone();
        }
        if let Some(bundle) = &self.bundle {
            config.prekey_bundle = Some(bundle.clone());
        }
        if let Some(fingerprint) = &self.fingerprint {
            if let Some(value) = rvpn_tls::fingerprint_from_str(fingerprint) {
                config.tls_fingerprint = value;
            }
        }
        if let Some(address) = &self.dashboard_listen {
            config.dashboard.enabled = true;
            config.dashboard.listen_address = address.clone();
        }
    }
}

struct Worker {
    stop: watch::Sender<bool>,
    ready: oneshot::Receiver<Option<String>>,
    done: oneshot::Receiver<std::result::Result<(), String>>,
    thread: Option<std::thread::JoinHandle<()>>,
    dns_warning: Option<String>,
}

impl Worker {
    fn start(config: ClientConfig, allow_dns_failure: bool) -> Result<Self> {
        config.dns_proxy.validate_system_dns(&config.tun)?;
        anyhow::ensure!(
            config.performance.worker_threads > 0,
            "performance.worker_threads must be greater than zero"
        );
        let (stop, mut stopped) = watch::channel(false);
        let (ready_tx, ready) = oneshot::channel();
        let (done_tx, done) = oneshot::channel();
        let thread = std::thread::Builder::new().name("rvpn-network".into()).spawn(move || {
            let result = (|| -> Result<()> {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(config.performance.worker_threads).enable_all().build()?;
                let result = runtime.block_on(async {
                    tokio::select! {
                        biased;
                        _ = stopped.changed() => Ok(()),
                        result = async {
                            rvpn_core::crypto::key_files::ensure_identity(&config.identity_key_file, "Client")?;
                            if config.tun.enabled {
                                // Validate key/bundle files before acknowledging a TUN generation.
                                crate::server_pool::ServerPool::from_config(&config).await?;
                                run_tun(config, ready_tx).await
                            } else {
                                crate::websocket::configure_endpoint_dns(&config)?;
                                run_socks5(config, ready_tx, allow_dns_failure).await
                            }
                        } => result,
                    }
                });
                // Cancellation drops the root future (including the TUN handle
                // and PID guard); shutdown drains/aborts every spawned child.
                runtime.shutdown_timeout(Duration::from_secs(2));
                result
            })().map_err(|error| format!("{error:#}"));
            let _ = done_tx.send(result);
        }).context("Failed to start network runtime")?;
        Ok(Self {
            stop,
            ready,
            done,
            thread: Some(thread),
            dns_warning: None,
        })
    }

    async fn wait_ready(&mut self) -> Result<Option<String>> {
        tokio::select! {
            result = &mut self.ready => match result {
                Ok(dns_warning) => Ok(dns_warning),
                Err(_) => Err(anyhow::anyhow!((&mut self.done).await.unwrap_or_else(|_| Err("Network worker exited unexpectedly".into())).err().unwrap_or_else(|| "Network stopped before readiness".into()))),
            },
            result = &mut self.done => Err(anyhow::anyhow!(result.unwrap_or_else(|_| Err("Network worker exited unexpectedly".into())).err().unwrap_or_else(|| "Network stopped before readiness".into()))),
        }
    }

    async fn stop(mut self) {
        let _ = self.stop.send(true);
        if let Some(thread) = self.thread.take() {
            if let Err(error) = tokio::task::spawn_blocking(move || thread.join()).await {
                tracing::warn!("Network runtime join: {error}");
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

struct PanelListener {
    task: tokio::task::JoinHandle<()>,
    address: String,
    local_address: Option<std::net::SocketAddr>,
}

impl PanelListener {
    async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for PanelListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn bind_panel(config: &ClientConfig) -> Result<Option<tokio::net::TcpListener>> {
    if !config.dashboard.enabled {
        return Ok(None);
    }
    anyhow::ensure!(
        !config.dashboard.allow_cidrs.is_empty()
            && config.dashboard.allow_cidrs.iter().all(|cidr| cidr.parse::<ip_network::IpNetwork>().is_ok()),
        "Invalid dashboard.allow_cidrs"
    );
    let listener = tokio::net::TcpListener::bind(&config.dashboard.listen_address)
        .await
        .with_context(|| {
            format!(
                "Failed to bind control panel to {}",
                config.dashboard.listen_address
            )
        })?;
    Ok(Some(listener))
}

async fn bind_recovery_panel(config: &mut ClientConfig) -> Result<tokio::net::TcpListener> {
    let mut dashboard = crate::config::DashboardConfig::default();
    dashboard.enabled = true;
    let socket = match tokio::net::TcpListener::bind(&dashboard.listen_address).await {
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            tokio::net::TcpListener::bind("127.0.0.1:0").await?
        }
        result => result?,
    };
    dashboard.listen_address = socket.local_addr()?.to_string();
    config.dashboard = dashboard;
    Ok(socket)
}

fn serve_panel(
    listener: tokio::net::TcpListener,
    config: &ClientConfig,
    state: Arc<dashboard::DashboardState>,
    panel: Arc<ControlPanel>,
) -> PanelListener {
    dashboard::init(state.clone());
    let allow = Arc::new(
        config
            .dashboard
            .allow_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse().ok())
            .collect(),
    );
    let local = listener.local_addr().ok();
    if let Some(local) = local {
        println!("Web 控制面板已启动，请在浏览器中访问：{}", panel_url(local));
        tracing::debug!("Control panel listening: {}", panel_url(local));
        if local.ip().is_unspecified() {
            println!("其他设备请使用本机 IP 和端口 {} 访问（受 allow_cidrs 限制）", local.port());
        }
    }
    PanelListener {
        task: tokio::spawn(crate::control_panel::serve(listener, state, allow, panel)),
        address: config.dashboard.listen_address.clone(),
        local_address: local,
    }
}

pub(crate) fn panel_url(mut address: std::net::SocketAddr) -> String {
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    format!("http://{address}/")
}

#[cfg(test)]
mod tests {
    use super::panel_url;

    #[test]
    fn panel_startup_urls_use_actual_ports_and_reachable_loopback_hosts() {
        for (listen, url) in [
            ("127.0.0.1:9800", "http://127.0.0.1:9800/"),
            ("0.0.0.0:19800", "http://127.0.0.1:19800/"),
            ("[::]:19801", "http://[::1]:19801/"),
            ("192.168.1.2:9800", "http://192.168.1.2:9800/"),
        ] {
            assert_eq!(panel_url(listen.parse().unwrap()), url);
        }
    }
}

pub(crate) fn awaits_server_import(config: &ClientConfig) -> bool {
    if config.server_address == "wss://vpn.example.com/api/v1/ws" {
        // Older release examples included this placeholder bundle path.
        return config.prekey_bundle.as_ref().is_none_or(|path| {
            path.ends_with("prekey-bundle.json") && matches!(path.try_exists(), Ok(false))
        });
    }
    config.server_address == crate::config::DEFAULT_SERVER_ADDRESS && config.prekey_bundle.is_none()
}

async fn start_ready(config: ClientConfig, allow_dns_failure: bool) -> Result<Worker> {
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } == 0 || config.tun.enabled || config.dns_proxy.takes_over_system_dns() {
        crate::linux_dns::recover().context("Failed to recover system DNS")?;
        crate::tun_routes::recover().context("Failed to recover TUN routes")?;
    }
    let mut worker = Worker::start(config, allow_dns_failure)?;
    match tokio::time::timeout(Duration::from_secs(15), worker.wait_ready()).await {
        Ok(Ok(dns_warning)) => {
            if let Some(warning) = &dns_warning {
                eprintln!("{warning}");
            }
            worker.dns_warning = dns_warning;
            Ok(worker)
        }
        failure => {
            worker.stop().await;
            match failure {
                Ok(Err(error)) => Err(error),
                _ => anyhow::bail!("Network startup timed out"),
            }
        }
    }
}

pub async fn run(
    mut config: ClientConfig,
    path: PathBuf,
    overrides: Overrides,
    mut startup_problem: Option<String>,
    logging: &rvpn_logging::ReloadableLogging,
) -> Result<()> {
    config.split_tunnel.subscriptions = Some(Arc::new(rvpn_split_tunnel::subscriptions::Subscriptions::open(&config.data_dir)));
    let awaiting_import = config.dashboard.enabled && awaits_server_import(&config);
    let mut setup_listen_override = None;
    let socket = match bind_panel(&config).await {
        Ok(Some(socket)) => Some(socket),
        Ok(None) => {
            tracing::info!("Web 控制面板未启用；可在配置文件 [dashboard] 中设置 enabled = true");
            None
        }
        Err(error) => {
            let socket = bind_recovery_panel(&mut config).await?;
            let port_busy = error.downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrInUse);
            if awaiting_import && port_busy {
                setup_listen_override = Some(config.dashboard.listen_address.clone());
            } else {
                startup_problem.get_or_insert_with(|| format!("WebUI 配置无效，已使用本地监听地址：{error:#}"));
            }
            Some(socket)
        }
    };
    let panel = Arc::new(ControlPanel::new(path, config.clone(), setup_listen_override)?);
    let (sender, mut requests) = mpsc::channel::<ApplyRequest>(8);
    panel.attach_applier(sender);
    let state = dashboard::global().unwrap_or_else(|| Arc::new(dashboard::DashboardState::new()));
    let sampler = tokio::spawn(dashboard::run_sampler(state.clone()));
    let _sampler_guard = OnDrop::new(move || sampler.abort());
    let mut listener = socket.map(|socket| serve_panel(socket, &config, state.clone(), panel.clone()));
    let (shutdown, mut stopped) = watch::channel(false);
    let signals = tokio::spawn(handle_signals(shutdown));
    let _signal_guard = OnDrop::new(move || signals.abort());
    let mut startup_error = None;
    let initial_network = if let Some(problem) = startup_problem {
        Err(anyhow::Error::msg(problem))
    } else if awaiting_import {
        println!("请在 Web 控制面板导入 rVPN:// 服务器链接，然后保存并应用。");
        Ok(None)
    } else {
        start_ready(config.clone(), true).await.map(Some)
    };
    let mut worker = match initial_network {
        Ok(Some(worker)) => {
            panel.set_dns_warning(worker.dns_warning.clone());
            logging.use_runtime_settings(&config.logging)?;
            tracing::info!("R-VPN Client v{} started", env!("CARGO_PKG_VERSION"));
            Some(worker)
        }
        Ok(None) => None,
        Err(error) => {
            if listener.is_none() {
                let socket = bind_recovery_panel(&mut config).await
                    .with_context(|| format!("VPN startup failed: {error:#}; could not start the local recovery panel"))?;
                panel.set_dashboard(config.dashboard.clone());
                listener = Some(serve_panel(socket, &config, state.clone(), panel.clone()));
            }
            eprintln!("VPN failed to start; control panel remains available: {error:#}");
            panel.set_runtime_error(format!("{error:#}"));
            startup_error = Some(format!("VPN 启动失败，WebUI 仍可用于修复配置：{error:#}"));
            None
        }
    };
    let mut started = worker.is_some();
    crate::service::report_startup(
        listener.as_ref().and_then(|panel| panel.local_address),
        startup_error,
        worker.as_ref().and_then(|worker| worker.dns_warning.as_deref()),
    )?;
    #[cfg(windows)]
    crate::service::windows::ready()?;
    loop {
        tokio::select! {
            _ = stopped.changed() => break,
            completed = async { match worker.as_mut() { Some(worker) => (&mut worker.done).await, None => std::future::pending().await } } => {
                if let Some(old) = worker.take() { old.stop().await; }
                let error = match completed { Ok(Err(error)) => error, _ => "VPN network runtime stopped".into() };
                if listener.is_none() { anyhow::bail!(error) }
                tracing::error!("{error}");
                let _ = crate::service::report_startup(listener.as_ref().and_then(|panel| panel.local_address), Some(error.clone()), None);
                panel.set_dns_warning(None);
                panel.set_runtime_error(error);
            }
            Some(mut request) = requests.recv() => {
                overrides.apply(&mut request.config);
                let mut candidate = request.config;
                candidate.split_tunnel.subscriptions = if candidate.data_dir == config.data_dir {
                    config.split_tunnel.subscriptions.clone()
                } else {
                    Some(Arc::new(rvpn_split_tunnel::subscriptions::Subscriptions::open(&candidate.data_dir)))
                };
                let outcome = async {
                    anyhow::ensure!(!awaiting_import || started || !awaits_server_import(&candidate),
                        "请先导入服务器链接，或填写服务器地址和公开预密钥包路径");
                    // Avoid creating files before the first successful network startup.
                    let mut prepared_log = started.then(|| logging.prepare(&candidate.logging)).transpose()?;
                    let same_address = candidate.dashboard.enabled && listener.as_ref().is_some_and(|old| old.address == candidate.dashboard.listen_address);
                    // Wildcard/loopback changes on the same port overlap. Stop
                    // only the accept loop; accepted WebSockets stay alive to
                    // receive the save result even while the listener moves.
                    let overlaps = !same_address && candidate.dashboard.enabled && listener.as_ref().is_some_and(|old| {
                        match (old.address.parse::<std::net::SocketAddr>(), candidate.dashboard.listen_address.parse::<std::net::SocketAddr>()) {
                            (Ok(old),Ok(new)) => old.port() == new.port(), _ => false,
                        }
                    });
                    if overlaps { if let Some(old) = listener.take() { old.stop().await; } }
                    let prepared_listener = if same_address { None } else { bind_panel(&candidate).await? };
                    let mut old_network = serde_json::to_value(&config)?;
                    let mut new_network = serde_json::to_value(&candidate)?;
                    let retry_dns = old_network == new_network
                        && worker.as_ref().is_some_and(|worker| worker.dns_warning.is_some());
                    for value in [&mut old_network, &mut new_network] { value.as_object_mut().unwrap().remove("logging"); value.as_object_mut().unwrap().remove("dashboard"); }
                    let rebuild = old_network != new_network || worker.is_none() || retry_dns;
                    if rebuild {
                        let allow_dns_failure = worker.is_none() || old_network["dns_proxy"] == new_network["dns_proxy"];
                        if let Some(old) = worker.take() { old.stop().await; }
                        match start_ready(candidate.clone(), allow_dns_failure).await {
                            Ok(new_worker) => {
                                if !started {
                                    match logging.prepare(&candidate.logging) {
                                        Ok(prepared) => prepared_log = Some(prepared),
                                        Err(error) => {
                                            new_worker.stop().await;
                                            return Err(error);
                                        }
                                    }
                                }
                                worker = Some(new_worker);
                            }
                            Err(error) if !started => return Err(error),
                            Err(error) => {
                                match start_ready(config.clone(), true).await {
                                    Ok(restored) => {
                                        panel.set_dns_warning(restored.dns_warning.clone());
                                        worker = Some(restored);
                                    }
                                    Err(restore) => {
                                        panel.set_dns_warning(None);
                                        panel.set_runtime_error(format!("应用失败：{error:#}；恢复网络失败：{restore:#}"));
                                    }
                                }
                                return Err(error.context("网络未切换到新配置，已尝试恢复原运行配置"));
                            }
                        }
                    }
                    if let Some(prepared_log) = prepared_log {
                        logging.apply(prepared_log)?;
                    }
                    started = true;
                    if !same_address {
                        if let Some(old) = listener.take() { old.stop().await; }
                        listener = prepared_listener.map(|socket| serve_panel(socket, &candidate, state.clone(), panel.clone()));
                    }
                    config = candidate;
                    let dns_warning = worker.as_ref().and_then(|worker| worker.dns_warning.as_deref());
                    panel.set_active(config.clone(), request.revision, dns_warning.map(str::to_owned));
                    if let Err(error) = crate::service::report_startup(listener.as_ref().and_then(|panel| panel.local_address), None, dns_warning) {
                        tracing::warn!("Could not update service startup report: {error:#}");
                    }
                    tracing::info!("Client configuration applied without process restart (network rebuilt: {rebuild})");
                    Ok::<(),anyhow::Error>(())
                }.await;
                if outcome.is_err() && listener.is_none() && config.dashboard.enabled {
                    // A same-port panel rebind or later network failure may
                    // have released the accept socket. Restore the old address.
                    match bind_panel(&config).await {
                        Ok(Some(socket)) => listener = Some(serve_panel(socket, &config, state.clone(), panel.clone())),
                        Err(error) => { tracing::error!("Could not restore control panel listener: {error:#}"); panel.set_runtime_error(format!("控制面板监听恢复失败：{error:#}")); }
                        _ => {},
                    }
                }
                let _ = request.reply.send(outcome.map_err(|error| format!("{error:#}")));
            }
        }
    }
    if let Some(worker) = worker {
        worker.stop().await;
    }
    Ok(())
}

/// Run in SOCKS5 proxy mode (Brook-style)
async fn run_socks5(
    config: ClientConfig,
    ready: oneshot::Sender<Option<String>>,
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
    let stats_manager = crate::stats::init_global_stats_manager_with_dir(config.data_dir.clone()).await;
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

        let http_proxy = crate::http_proxy::HttpProxy::new(
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
            let system_dns = takeover.then(crate::windows_dns::SystemDns::take_over).transpose()?;
            #[cfg(target_os = "macos")]
            let system_dns = takeover.then(crate::macos_dns::SystemDns::take_over).transpose()?;
            #[cfg(target_os = "linux")]
            let system_dns = if takeover {
                crate::linux_dns::SystemDns::install(
                    config.dns_proxy.effective_listener().parse()?,
                    true,
                    &config.dns_proxy.nameservers,
                )?
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
pub(crate) async fn check_dns_loopback(listener: &tokio::net::UdpSocket) -> Result<()> {
    let address = listener.local_addr()?;
    let probe = tokio::net::UdpSocket::bind(SocketAddr::new(address.ip(), 0)).await?;
    probe.send_to(&[], address).await?;
    let mut packet = vec![0; 65535];
    tokio::time::timeout(Duration::from_secs(2), listener.peek_from(&mut packet))
        .await.with_context(|| format!("DNS 回环监听 {address} 未收到探测数据"))??;
    Ok(())
}

async fn bind_dns_proxy(
    config: &ClientConfig,
    proxy: &Socks5Proxy,
) -> Result<(Arc<crate::dns_proxy::DnsProxy>, tokio::net::UdpSocket, Option<tokio::net::UdpSocket>)> {
    let address: SocketAddr = config.dns_proxy.effective_listener().parse()?;
    let nameservers = rvpn_split_tunnel::dns_cache::DnsUpstreams::new(&config.dns_proxy.nameservers)?;
    nameservers.validate_listener(address)?;
    let extra_hosts = config.extra_servers.iter().map(|server| parse_server_url(&server.address).0).collect();
    let doh_hosts = config.dns_proxy.nameservers.iter()
        .filter_map(|endpoint| rvpn_split_tunnel::dns_cache::doh_upstream_hostname(endpoint)).collect();
    let dns = Arc::new(crate::dns_proxy::DnsProxy::new(
        address, proxy.server_host().to_string(), proxy.server_port(), proxy.server_path(),
        proxy.tls_fingerprint(), proxy.identity_key(), proxy.server_bundle(), proxy.split_tunnel(),
        proxy.dns_resolver(), nameservers, extra_hosts, doh_hosts, config.dns_proxy.host_records()?,
    ));
    let socket = bind_dns_listener(address).await?;
    let secondary = if config.dns_proxy.takes_over_system_dns() {
        let address = crate::config::DnsProxyConfig::SYSTEM_DNS_V6.parse()?;
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
async fn run_tun(_: ClientConfig, _: oneshot::Sender<Option<String>>) -> Result<()> {
    anyhow::bail!("Managed desktop TUN routing and DNS currently require Linux")
}

#[cfg(target_os = "linux")]
async fn run_tun(mut config: ClientConfig, ready: oneshot::Sender<Option<String>>) -> Result<()> {
    use crate::tun::TunDevice;
    use crate::tunnel::VpnTunnel;

    anyhow::ensure!(config.extra_servers.is_empty() && config.routing.is_empty(),
        "Multi-server routing is supported only in proxy mode");
    anyhow::ensure!(config.dns_proxy.enabled, "TUN requires the local DNS proxy for domain rules");
    if config.dns_proxy.nameservers.is_empty() {
        config.dns_proxy.nameservers.clone_from(&config.tun.dns_servers);
    }
    crate::websocket::configure_endpoint_dns(&config)?;
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
                let mut routes = crate::tun_routes::Routes::new(&device.name()?, &tun_config.routes, direct, forced, full_unknown)?;
                for address in split.server_ipv4_exceptions().await.into_iter().chain(upstream_ips.iter().copied()) {
                    routes.pin(address)?;
                }
                routes.activate()?;
                let routes = Arc::new(routes);
                let weak = Arc::downgrade(&routes);
                crate::websocket::set_endpoint_route_hook(Some(Arc::new(move |address| {
                    if let Some(routes) = weak.upgrade() { routes.pin(address)?; }
                    Ok(())
                })));
                let _hook = OnDrop::new(|| crate::websocket::set_endpoint_route_hook(None));
                dns.set_tun_routes(&routes);
                let fallback_dns = if config.dns_proxy.nameservers.is_empty() {
                    &tun_config.dns_servers
                } else {
                    &config.dns_proxy.nameservers
                };
                let _dns = crate::linux_dns::SystemDns::install(
                    listen,
                    config.dns_proxy.takes_over_system_dns(),
                    fallback_dns,
                )?;
                dashboard::TUN_READY.store(true, std::sync::atomic::Ordering::Relaxed);
                let _status = OnDrop::new(|| dashboard::TUN_READY.store(false, std::sync::atomic::Ordering::Relaxed));
                failures = 0;
                if let Some(ready) = ready.take() {
                    let _ = ready.send(None);
                }
                let (_shutdown, shutdown) = watch::channel(false);
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
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    tokio::select! {
        result = connection => result,
        result = Arc::clone(&dns).run_with_sockets(socket, secondary) => result.context("TUN DNS listener stopped"),
    }
}

/// Handle shutdown signals (SIGINT, SIGTERM on Unix; Ctrl+C on Windows)
async fn handle_signals(shutdown_tx: watch::Sender<bool>) {
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
        if crate::service::windows::is_service() {
            crate::service::windows::wait_stop().await;
        } else {
            tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        }
        info!("Received shutdown request, initiating graceful shutdown...");
    }

    let _ = shutdown_tx.send(true);
}

fn check_format(path: &Path) -> Result<()> {
    anyhow::ensure!(
        matches!(path.extension().and_then(|ext| ext.to_str()), Some("toml" | "json")),
        "Configuration file must have a .toml or .json extension: {}",
        path.display()
    );
    Ok(())
}

fn create_initial_config(path: &Path) -> Result<()> {
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

pub async fn async_main(args: Args) -> Result<ExitCode> {
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
                let mut config = crate::control_panel::setup_config();
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
    let overrides = Overrides {
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

    run(config, args.config, overrides, startup_problem, logging).await
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
    info!("Client public identity (Ed25519, base64): {}", BASE64.encode(identity.verifying_key.as_bytes()));
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
