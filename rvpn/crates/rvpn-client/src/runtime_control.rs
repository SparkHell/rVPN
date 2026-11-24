//! The panel lives on the process runtime; every VPN generation owns a separate
//! runtime. Dropping that runtime cancels all nested relay/DNS/pool tasks before
//! listeners are reused, including tasks spawned by library components.
use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{
    config::ClientConfig,
    control_panel::{ApplyRequest, ControlPanel},
    dashboard,
};

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
                                crate::run_tun(config, ready_tx).await
                            } else {
                                crate::websocket::configure_endpoint_dns(&config)?;
                                crate::run_socks5(config, ready_tx, allow_dns_failure).await
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
    let _sampler_guard = crate::OnDrop::new(move || sampler.abort());
    let mut listener = socket.map(|socket| serve_panel(socket, &config, state.clone(), panel.clone()));
    let (shutdown, mut stopped) = watch::channel(false);
    let signals = tokio::spawn(crate::handle_signals(shutdown));
    let _signal_guard = crate::OnDrop::new(move || signals.abort());
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
