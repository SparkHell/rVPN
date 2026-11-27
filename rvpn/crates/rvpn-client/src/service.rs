//! Native system service registration. Installation does not start the VPN.
use anyhow::{Context, Result};
use clap::Subcommand;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Subcommand)]
pub enum ServiceAction {
    Install,
    Uninstall,
    Start,
    Stop,
    Status,
    /// Internal Windows SCM entry point
    #[command(hide = true)]
    Run {
        #[arg(long)]
        working_directory: PathBuf,
    },
}

#[cfg(any(target_os = "macos", windows, test))]
fn privileged_action(action: &ServiceAction) -> Option<&'static str> {
    match action {
        ServiceAction::Install => Some("install"),
        ServiceAction::Uninstall => Some("uninstall"),
        ServiceAction::Start => Some("start"),
        ServiceAction::Stop => Some("stop"),
        ServiceAction::Status | ServiceAction::Run { .. } => None,
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_sudo(exe: &Path, non_interactive: bool) -> Command {
    let mut command = Command::new("/usr/bin/sudo");
    if non_interactive {
        command.arg("-n");
    }
    command.arg("--").arg(exe);
    command
}

#[cfg(any(target_os = "macos", test))]
fn macos_elevation_command(exe: &Path, config: &Path, action: &str) -> Command {
    let mut command = macos_sudo(exe, false);
    command
        .arg("--config")
        .arg(config)
        .args(["service", action]);
    command
}

#[cfg(any(target_os = "macos", test))]
fn foreground_requests_admin(config: &crate::config::ClientConfig) -> bool {
    !config.tun.enabled
        && config.dns_proxy.takes_over_system_dns()
        && config.dns_proxy.validate_system_dns(&config.tun).is_ok()
}

#[cfg(target_os = "macos")]
pub fn authorize_foreground(config: &crate::config::ClientConfig) {
    use std::io::IsTerminal;
    use std::os::unix::process::CommandExt;

    if unsafe { libc::geteuid() } == 0
        || std::env::var_os("RVPN_SYSTEM_SERVICE").is_some()
        || !std::io::stdin().is_terminal()
        || !std::io::stderr().is_terminal()
        || !foreground_requests_admin(config)
    {
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            eprintln!("无法定位客户端以请求管理员权限：{error}");
            return;
        }
    };
    eprintln!("系统 DNS 接管需要管理员权限，正在通过 sudo 请求授权…");
    // Authenticate before replacing this process so refusing authorization
    // still leaves the normal foreground startup and Web UI available.
    // During the prompt, Ctrl-C cancels sudo instead of killing the client too.
    let _interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok();
    match Command::new("/usr/bin/sudo").arg("-v").status() {
        Ok(status) if status.success() => {
            let error = macos_sudo(&exe, true).args(std::env::args_os().skip(1)).exec();
            eprintln!("无法启动管理员客户端，将继续以普通权限运行：{error}");
        }
        Ok(_) => eprintln!("未取得管理员授权，将继续以普通权限运行。"),
        Err(error) => eprintln!("无法请求管理员权限，将继续以普通权限运行：{error}"),
    }
}

#[cfg(any(unix, test))]
fn output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute {program}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::ensure!(
        output.status.success(),
        "{program} {} failed ({}):\n{}{}",
        args.join(" "),
        output.status,
        stdout,
        stderr
    );
    Ok(stdout.into_owned())
}

#[cfg(unix)]
fn run(program: &str, args: &[&str]) -> Result<()> {
    output(program, args).map(|_| ())
}

// systemd interprets percent specifiers and dollar expansions inside quotes.
#[cfg(any(target_os = "linux", test))]
fn systemd_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}

#[cfg(any(target_os = "macos", test))]
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(target_os = "linux", test))]
fn unit(exe: &str, config: &str, cwd: &str) -> String {
    // WorkingDirectory consumes an unquoted path. A trailing slash keeps
    // trailing whitespace or a backslash in the directory name literal.
    let cwd = cwd.trim_end_matches('/').replace('%', "%%");
    let metadata = hex::encode(config);
    format!("# rvpn-config: {metadata}\n[Unit]\nDescription=R-VPN Client\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nEnvironment=RVPN_SYSTEM_SERVICE=1\nWorkingDirectory={cwd}/\nExecStart={} --config {}\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=30\n\n[Install]\nWantedBy=multi-user.target\n",
        systemd_quote(exe).replace('$', "$$"), systemd_quote(config).replace('$', "$$"))
}

#[cfg(any(target_os = "macos", test))]
fn plist(exe: &str, config: &str, cwd: &str) -> String {
    let metadata = hex::encode(config);
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<!-- rvpn-config: {metadata} -->\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.rvpn.client</string>\n<key>ProgramArguments</key><array><string>{}</string><string>--config</string><string>{}</string></array>\n<key>EnvironmentVariables</key><dict><key>RVPN_SYSTEM_SERVICE</key><string>1</string></dict>\n<key>WorkingDirectory</key><string>{}</string>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>StandardOutPath</key><string>/var/log/rvpn-client.log</string>\n<key>StandardErrorPath</key><string>/var/log/rvpn-client.log</string>\n<key>ThrottleInterval</key><integer>5</integer>\n</dict></plist>\n", xml(exe), xml(config), xml(cwd))
}

#[cfg(unix)]
fn write_definition(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .context(
            "Cannot create service definition (already installed, or insufficient privileges)",
        )?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

pub fn execute(action: &ServiceAction, config: &Path) -> Result<()> {
    #[cfg(windows)]
    if privileged_action(action).is_some() && !windows::is_elevated()
    {
        println!("需要管理员权限，正在请求 UAC 授权…");
        return windows::elevate(action, config);
    }
    #[cfg(target_os = "macos")]
    if let Some(action) = privileged_action(action) {
        if unsafe { libc::geteuid() } != 0 {
            println!("需要管理员权限，正在通过 sudo 请求授权…");
            let status = macos_elevation_command(&std::env::current_exe()?, config, action)
                .status()
                .context("无法通过 sudo 请求 macOS 管理员权限")?;
            anyhow::ensure!(status.success(), "macOS 服务操作未完成（sudo {status}）");
            return Ok(());
        }
    }
    if matches!(action, ServiceAction::Start) {
        crate::config::ClientConfig::load(&installed_config(config)?)
            .context("无法启动服务：读取已安装服务配置失败")?;
    }
    let since = std::time::SystemTime::now();
    execute_native(action, config)
        .map_err(|error| {
            if matches!(action, ServiceAction::Start) {
                startup_error(error, since)
            } else {
                error
            }
        })
        .with_context(|| format!("服务操作失败：{action:?}"))?;
    match action {
        ServiceAction::Install => {
            println!("服务安装成功，已设置开机启动。运行 rvpn service start 启动服务。")
        }
        ServiceAction::Uninstall => println!("服务卸载成功。"),
        ServiceAction::Start => {
            let path = installed_config(config)?;
            let config = crate::config::ClientConfig::load(&path)?;
            let report =
                wait_startup(&report_directory()?).map_err(|error| startup_error(error, since))?;
            if report.error.is_none() {
                println!("服务已启动。");
            }
            if let Some(url) = report.webui {
                println!("WebUI：{url}");
            } else if !config.dashboard.enabled {
                println!("WebUI 未启用；请在服务配置的 [dashboard] 中设置 enabled = true。");
            }
            if let Some(error) = report.error {
                anyhow::bail!("{error}");
            }
            if let Some(warning) = report.dns_warning {
                eprintln!("{warning}");
            }
        }
        ServiceAction::Stop => println!("服务已停止。"),
        _ => {}
    }
    Ok(())
}

fn startup_error(error: anyhow::Error, since: std::time::SystemTime) -> anyhow::Error {
    let details = (|| -> Result<String> {
        let path = report_directory()?.join("service-startup.json");
        anyhow::ensure!(
            std::fs::metadata(&path)?.modified()? >= since,
            "Old startup report"
        );
        let report: StartupReport = serde_json::from_slice(&std::fs::read(path)?)?;
        report.error.context("No startup error")
    })();
    if let Ok(details) = details {
        return error.context(details);
    }
    #[cfg(target_os = "linux")]
    if let Ok(logs) = output(
        "journalctl",
        &["-u", "rvpn-client", "-n", "20", "--no-pager"],
    ) {
        return error.context(logs);
    }
    #[cfg(target_os = "macos")]
    if let Ok(logs) = output("tail", &["-n", "20", "/var/log/rvpn-client.log"]) {
        return error.context(logs);
    }
    error
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StartupReport {
    pid: u32,
    webui: Option<String>,
    error: Option<String>,
    dns_warning: Option<String>,
}

pub(crate) fn managed_process() -> bool {
    #[cfg(windows)]
    let managed = windows::is_service();
    #[cfg(unix)]
    let managed = std::env::var_os("RVPN_SYSTEM_SERVICE").is_some()
        // Also recognize definitions installed by older releases, which did
        // not set our marker. System daemons are children of systemd/launchd.
        || unsafe { libc::getppid() == 1 };
    #[cfg(not(any(unix, windows)))]
    let managed = false;
    managed
}

pub fn report_startup(
    address: Option<std::net::SocketAddr>,
    error: Option<String>,
    dns_warning: Option<&str>,
) -> Result<()> {
    if !managed_process() {
        return Ok(());
    }
    let directory = report_directory()?;
    std::fs::create_dir_all(&directory)
        .context("Cannot create service startup report directory")?;
    let report = StartupReport {
        pid: std::process::id(),
        webui: address.map(crate::runtime_control::panel_url),
        error,
        dns_warning: dns_warning.map(str::to_owned),
    };
    let mut file = tempfile::NamedTempFile::new_in(&directory)?;
    serde_json::to_writer(&mut file, &report)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    file.persist(directory.join("service-startup.json"))?;
    Ok(())
}

fn report_directory() -> Result<PathBuf> {
    // Both the CLI user and the system service must resolve the same directory.
    // Per-user data_dir / temporary directories differ under LocalSystem/root.
    #[cfg(windows)]
    {
        Ok(
            PathBuf::from(std::env::var_os("ProgramData").context("ProgramData is not set")?)
                .join("rvpn-client"),
        )
    }
    #[cfg(target_os = "linux")]
    {
        Ok(PathBuf::from("/run/rvpn-client"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(PathBuf::from("/var/run/rvpn-client"))
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    anyhow::bail!("Unsupported system service platform")
}

fn service_pid() -> Result<u32> {
    #[cfg(windows)]
    {
        windows::process_id()
    }
    #[cfg(target_os = "linux")]
    {
        Ok(output(
            "systemctl",
            &["show", "--property=MainPID", "--value", "rvpn-client"],
        )?
        .trim()
        .parse()?)
    }
    #[cfg(target_os = "macos")]
    {
        let status = output("launchctl", &["print", "system/com.rvpn.client"])?;
        Ok(status
            .lines()
            .find_map(|line| line.trim().strip_prefix("pid = "))
            .context("Service has no running process")?
            .parse()?)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    anyhow::bail!("Unsupported service platform")
}

fn wait_startup(data_dir: &Path) -> Result<StartupReport> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
    loop {
        let pid = service_pid()?;
        anyhow::ensure!(pid != 0, "服务启动失败，进程已经退出。请检查服务日志。");
        if let Some(report) = read_startup(data_dir, pid)? {
            return Ok(report);
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "等待服务就绪超时；请查看服务日志。"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn read_startup(data_dir: &Path, pid: u32) -> Result<Option<StartupReport>> {
    let bytes = match std::fs::read(data_dir.join("service-startup.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("无法读取服务启动结果"),
    };
    let report: StartupReport = serde_json::from_slice(&bytes).context("服务启动结果格式错误")?;
    Ok((report.pid == pid).then_some(report))
}

fn installed_config(_fallback: &Path) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        windows::installed_config()
    }
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        let definition = std::fs::read_to_string("/etc/systemd/system/rvpn-client.service")?;
        #[cfg(target_os = "macos")]
        let definition = std::fs::read_to_string("/Library/LaunchDaemons/com.rvpn.client.plist")?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(path) = definition_config(&definition)? {
            return Ok(path);
        }
    }
    #[cfg(not(windows))]
    anyhow::bail!(
        "无法从服务定义读取配置路径；请检查服务定义（当前命令配置：{}）",
        _fallback.display()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn definition_config(definition: &str) -> Result<Option<PathBuf>> {
    if let Some(value) = definition.lines().find_map(|line| {
        line.strip_prefix("# rvpn-config: ").or_else(|| {
            line.strip_prefix("<!-- rvpn-config: ")
                .and_then(|s| s.strip_suffix(" -->"))
        })
    }) {
        return Ok(Some(PathBuf::from(String::from_utf8(hex::decode(value)?)?)));
    }
    // Read definitions generated by releases before the metadata comment.
    if let Some(command) = definition
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))
    {
        let mut args = Vec::new();
        let mut word = String::new();
        let mut quoted = false;
        let mut chars = command.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\"' => quoted = !quoted,
                '\\' => word.push(
                    chars
                        .next()
                        .context("Incomplete escape in service command")?,
                ),
                ch if ch.is_whitespace() && !quoted => {
                    if !word.is_empty() {
                        args.push(std::mem::take(&mut word));
                    }
                }
                ch => word.push(ch),
            }
        }
        anyhow::ensure!(!quoted, "Unclosed quote in service command");
        if !word.is_empty() {
            args.push(word);
        }
        return Ok(args
            .windows(2)
            .find(|pair| pair[0] == "--config")
            .map(|pair| PathBuf::from(pair[1].replace("%%", "%").replace("$$", "$"))));
    }
    if let Some((_, arguments)) = definition.split_once("<key>ProgramArguments</key>") {
        let array = arguments
            .split_once("<array>")
            .and_then(|(_, rest)| rest.split_once("</array>").map(|(array, _)| array))
            .context("Missing service argument array")?;
        let args: Vec<&str> = array
            .split("<string>")
            .skip(1)
            .filter_map(|value| value.split_once("</string>").map(|(text, _)| text))
            .collect();
        return Ok(args
            .windows(2)
            .find(|pair| pair[0] == "--config")
            .map(|pair| {
                PathBuf::from(
                    pair[1]
                        .replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("&quot;", "\"")
                        .replace("&apos;", "'")
                        .replace("&amp;", "&"),
                )
            }));
    }
    Ok(None)
}

fn execute_native(action: &ServiceAction, config: &Path) -> Result<()> {
    if let ServiceAction::Run { working_directory } = action {
        #[cfg(windows)]
        {
            std::env::set_current_dir(working_directory)?;
            return windows::dispatch();
        }
        #[cfg(not(windows))]
        {
            let _ = working_directory;
            anyhow::bail!("service run is only used by Windows SCM");
        }
    }
    // Resolve paths before installing so services don't depend on the manager's CWD.
    let paths = if matches!(action, ServiceAction::Install) {
        let config = config
            .canonicalize()
            .context("Service installation requires an existing config file")?;
        crate::config::ClientConfig::load(&config)?;
        let exe = std::env::current_exe()?;
        let cwd = std::env::current_dir()?;
        for path in [&exe, &config, &cwd] {
            let value = path.to_str().context("Service paths must be UTF-8")?;
            anyhow::ensure!(!value.contains(['\n', '\r', '\0']), "Invalid service path");
        }
        Some((exe, config, cwd))
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    {
        let path = Path::new("/etc/systemd/system/rvpn-client.service");
        match action {
            ServiceAction::Install => {
                let (exe, config, cwd) = paths.unwrap();
                anyhow::ensure!(!path.exists(), "Service already installed; uninstall first");
                write_definition(
                    path,
                    &unit(
                        exe.to_str().unwrap(),
                        config.to_str().unwrap(),
                        cwd.to_str().unwrap(),
                    ),
                )?;
                run("systemctl", &["daemon-reload"])?;
                run("systemctl", &["enable", "rvpn-client"])
            }
            ServiceAction::Uninstall => {
                run("systemctl", &["disable", "--now", "rvpn-client"])?;
                std::fs::remove_file(path)?;
                run("systemctl", &["daemon-reload"])
            }
            ServiceAction::Start => run("systemctl", &["start", "rvpn-client"]),
            ServiceAction::Stop => run("systemctl", &["stop", "rvpn-client"]),
            ServiceAction::Status => {
                print!(
                    "{}",
                    output("systemctl", &["status", "--no-pager", "rvpn-client"])?
                );
                Ok(())
            }
            ServiceAction::Run { .. } => unreachable!(),
        }
    }
    #[cfg(target_os = "macos")]
    {
        const PLIST: &str = "/Library/LaunchDaemons/com.rvpn.client.plist";
        match action {
            ServiceAction::Install => {
                use std::os::unix::fs::PermissionsExt;
                let (exe, config, cwd) = paths.unwrap();
                anyhow::ensure!(
                    !Path::new(PLIST).exists(),
                    "Service already installed; uninstall first"
                );
                write_definition(
                    Path::new(PLIST),
                    &plist(
                        exe.to_str().unwrap(),
                        config.to_str().unwrap(),
                        cwd.to_str().unwrap(),
                    ),
                )?;
                std::fs::set_permissions(PLIST, std::fs::Permissions::from_mode(0o644))?;
                Ok(())
            }
            ServiceAction::Uninstall => {
                if Command::new("launchctl")
                    .args(["print", "system/com.rvpn.client"])
                    .output()?
                    .status
                    .success()
                {
                    run("launchctl", &["bootout", "system/com.rvpn.client"])?;
                }
                std::fs::remove_file(PLIST)?;
                Ok(())
            }
            ServiceAction::Start => {
                if output("launchctl", &["print", "system/com.rvpn.client"]).is_err() {
                    run("launchctl", &["bootstrap", "system", PLIST])?;
                } else {
                    run("launchctl", &["kickstart", "system/com.rvpn.client"])?;
                }
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
                loop {
                    let state = output("launchctl", &["print", "system/com.rvpn.client"])?;
                    if state.lines().any(|line| line.trim() == "state = running") {
                        return Ok(());
                    }
                    if std::time::Instant::now() >= deadline {
                        let logs = output("tail", &["-n", "20", "/var/log/rvpn-client.log"])
                            .unwrap_or_else(|e| format!("{e:#}"));
                        anyhow::bail!("等待服务启动超时：\n{state}\n{logs}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
            ServiceAction::Stop => run("launchctl", &["bootout", "system/com.rvpn.client"]),
            ServiceAction::Status => {
                print!(
                    "{}",
                    output("launchctl", &["print", "system/com.rvpn.client"])?
                );
                Ok(())
            }
            ServiceAction::Run { .. } => unreachable!(),
        }
    }
    #[cfg(windows)]
    {
        match action {
            ServiceAction::Install => {
                use windows_service::{
                    service::{
                        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType,
                        ServiceType,
                    },
                    service_manager::{ServiceManager, ServiceManagerAccess},
                };
                let (exe, config, cwd) = paths.unwrap();
                let manager = ServiceManager::local_computer(
                    None::<&str>,
                    ServiceManagerAccess::CREATE_SERVICE,
                )?;
                manager.create_service(
                    &ServiceInfo {
                        name: "rvpn-client".into(),
                        display_name: "R-VPN Client".into(),
                        service_type: ServiceType::OWN_PROCESS,
                        start_type: ServiceStartType::AutoStart,
                        error_control: ServiceErrorControl::Normal,
                        executable_path: exe,
                        launch_arguments: vec![
                            "--config".into(),
                            config.into_os_string(),
                            "service".into(),
                            "run".into(),
                            "--working-directory".into(),
                            cwd.into_os_string(),
                        ],
                        dependencies: vec![],
                        account_name: None,
                        account_password: None,
                    },
                    ServiceAccess::QUERY_STATUS,
                )?;
                Ok(())
            }
            ServiceAction::Uninstall => {
                use windows_service::{
                    service::ServiceAccess,
                    service_manager::{ServiceManager, ServiceManagerAccess},
                };
                windows::manage(&ServiceAction::Stop)?;
                let manager =
                    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
                manager
                    .open_service("rvpn-client", ServiceAccess::DELETE)?
                    .delete()?;
                Ok(())
            }
            ServiceAction::Start | ServiceAction::Stop | ServiceAction::Status => {
                windows::manage(action)
            }
            ServiceAction::Run { .. } => unreachable!(),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = paths;
        anyhow::bail!("System services are unsupported on this platform")
    }
}

#[cfg(windows)]
pub mod windows {
    use super::*;
    use clap::Parser;
    use std::sync::OnceLock;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    static STOP: OnceLock<tokio::sync::watch::Sender<bool>> = OnceLock::new();
    static STATUS: OnceLock<service_control_handler::ServiceStatusHandle> = OnceLock::new();
    define_windows_service!(ffi_main, service_main);

    pub fn is_elevated() -> bool {
        // This checks the effective token, including UAC's filtered admin token.
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
    }

    fn ps_literal(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    fn elevation_script(
        exe: &Path,
        config: &Path,
        cwd: &Path,
        action: &str,
        log: &Path,
    ) -> Result<String> {
        Ok(format!(
            "$ErrorActionPreference = 'Continue'; $global:LASTEXITCODE = 1; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding; Set-Location -LiteralPath {}; & {} '--config' {} 'service' {} 2>&1 | ForEach-Object {{ $_.ToString() }} | Out-File -LiteralPath {} -Encoding utf8 -Width 4096; exit $LASTEXITCODE",
            ps_literal(cwd.to_str().context("Working directory must be UTF-8")?),
            ps_literal(exe.to_str().context("Executable path must be UTF-8")?),
            ps_literal(config.to_str().context("Config path must be UTF-8")?),
            ps_literal(action),
            ps_literal(log.to_str().context("UAC output path must be UTF-8")?),
        ))
    }

    pub fn elevate(action: &ServiceAction, config: &Path) -> Result<()> {
        use base64::Engine;
        let action = privileged_action(action).context("This service action cannot be elevated")?;
        let log = tempfile::NamedTempFile::new()
            .context("Cannot create UAC output file")?
            .into_temp_path();
        let exe = std::env::current_exe()?;
        let cwd = std::env::current_dir()?;
        let script = elevation_script(&exe, config, &cwd, action, &log)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            script
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        // Only the encoded, literal-quoted command crosses the elevation boundary.
        // The parent waits and relays output and the exit code to the original terminal.
        let launcher = format!(
            "$ErrorActionPreference = 'Stop'; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding; try {{ $p = Start-Process -FilePath \"$PSHOME\\powershell.exe\" -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile -NonInteractive -EncodedCommand {encoded}' -Wait -PassThru; exit $p.ExitCode }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
        );
        let result = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &launcher])
            .output()
            .context("无法请求 UAC 授权")?;
        let contents = std::fs::read_to_string(&log).context("无法读取提权操作结果")?;
        let contents = contents.trim_start_matches('\u{feff}');
        if result.status.success() {
            print!("{contents}");
            Ok(())
        } else {
            anyhow::bail!(
                "UAC 授权被取消或服务操作失败（{}）：\n{}{}",
                result.status,
                contents,
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }

    pub fn installed_config() -> Result<PathBuf> {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service("rvpn-client", ServiceAccess::QUERY_CONFIG)?;
        let command = service.query_config()?.executable_path;
        let command: Vec<u16> = command.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut count = 0;
        let argv = unsafe {
            windows_sys::Win32::UI::Shell::CommandLineToArgvW(command.as_ptr(), &mut count)
        };
        anyhow::ensure!(
            !argv.is_null(),
            "Cannot parse installed service command: {}",
            std::io::Error::last_os_error()
        );
        let mut args = Vec::new();
        unsafe {
            for i in 0..count as usize {
                let ptr = *argv.add(i);
                let mut len = 0;
                while *ptr.add(len) != 0 {
                    len += 1;
                }
                args.push(std::ffi::OsString::from_wide(std::slice::from_raw_parts(
                    ptr, len,
                )));
            }
            windows_sys::Win32::Foundation::LocalFree(argv.cast());
        }
        args.windows(2)
            .find(|pair| pair[0] == "--config")
            .map(|pair| PathBuf::from(&pair[1]))
            .context("Installed service has no --config path")
    }

    pub fn process_id() -> Result<u32> {
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service("rvpn-client", ServiceAccess::QUERY_STATUS)?;
        service.query_status()?.process_id.context("服务进程已退出")
    }

    fn wait_state(
        service: &windows_service::service::Service,
        expected: ServiceState,
    ) -> Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let status = service.query_status()?;
            if status.current_state == expected {
                return Ok(());
            }
            anyhow::ensure!(
                expected != ServiceState::Running || status.current_state != ServiceState::Stopped,
                "服务启动失败，服务已退出：{:?}。请检查服务日志。",
                status.exit_code
            );
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "等待服务状态 {:?} 超时（当前状态：{:?}）",
                expected,
                status.current_state
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    pub fn manage(action: &ServiceAction) -> Result<()> {
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let access = ServiceAccess::QUERY_STATUS
            | match action {
                ServiceAction::Start => ServiceAccess::START,
                ServiceAction::Stop => ServiceAccess::STOP,
                _ => ServiceAccess::empty(),
            };
        let service = manager.open_service("rvpn-client", access)?;
        let status = service.query_status()?;
        match action {
            ServiceAction::Start => {
                if status.current_state == ServiceState::StopPending {
                    wait_state(&service, ServiceState::Stopped)?;
                }
                let current = service.query_status()?.current_state;
                if current != ServiceState::Running && current != ServiceState::StartPending {
                    service.start::<&str>(&[])?;
                }
                wait_state(&service, ServiceState::Running)
            }
            ServiceAction::Stop => {
                if status.current_state == ServiceState::StartPending {
                    wait_state(&service, ServiceState::Running)?;
                }
                let current = service.query_status()?.current_state;
                if current != ServiceState::Stopped && current != ServiceState::StopPending {
                    service.stop()?;
                }
                wait_state(&service, ServiceState::Stopped)
            }
            ServiceAction::Status => {
                let state = match status.current_state {
                    ServiceState::Running => "运行中",
                    ServiceState::Stopped => "已停止",
                    ServiceState::StartPending => "正在启动",
                    ServiceState::StopPending => "正在停止",
                    _ => "状态转换中",
                };
                println!("服务 rvpn-client：{state}");
                if status.exit_code != ServiceExitCode::Win32(0) {
                    println!("上次退出代码：{:?}", status.exit_code);
                }
                Ok(())
            }
            _ => unreachable!(),
        }
    }

    pub fn ready() -> Result<()> {
        if let Some(handle) = STATUS.get() {
            handle.set_service_status(service_status(
                ServiceState::Running,
                ServiceExitCode::Win32(0),
            ))?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod elevation_tests {
        use super::*;

        #[test]
        fn elevated_command_preserves_paths_output_and_failure_code() {
            use base64::Engine;
            let temp = tempfile::tempdir().unwrap();
            let cwd = temp.path().join("客户端 O'Brien $config `test");
            std::fs::create_dir(&cwd).unwrap();
            let exe = cwd.join("fake client.cmd");
            std::fs::write(
                &exe,
                "@echo off\r\necho service output\r\necho service failure 1>&2\r\nexit /b 7\r\n",
            )
            .unwrap();
            let log = tempfile::NamedTempFile::new_in(&cwd)
                .unwrap()
                .into_temp_path();
            let script =
                elevation_script(&exe, &cwd.join("client.toml"), &cwd, "install", &log).unwrap();
            let encoded = base64::engine::general_purpose::STANDARD.encode(
                script
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            );
            let result = Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(7),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let text = std::fs::read_to_string(&log).unwrap();
            assert!(text.contains("service output"), "{text}");
            assert!(text.contains("service failure"), "{text}");
        }
    }

    fn service_status(state: ServiceState, exit_code: ServiceExitCode) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code,
            checkpoint: if state == ServiceState::StartPending {
                1
            } else {
                0
            },
            wait_hint: if state == ServiceState::StartPending {
                std::time::Duration::from_secs(25)
            } else {
                std::time::Duration::ZERO
            },
            process_id: None,
        }
    }

    pub fn dispatch() -> Result<()> {
        service_dispatcher::start("rvpn-client", ffi_main)?;
        Ok(())
    }

    pub fn is_service() -> bool {
        STOP.get().is_some()
    }

    pub async fn wait_stop() {
        if let Some(tx) = STOP.get() {
            let mut rx = tx.subscribe();
            if !*rx.borrow() {
                let _ = rx.changed().await;
            }
        } else {
            std::future::pending::<()>().await;
        }
    }

    fn service_main(_: Vec<std::ffi::OsString>) {
        if let Err(e) = run_service() {
            eprintln!("R-VPN service failed: {e:#}");
        }
    }

    fn run_service() -> Result<()> {
        let (tx, _) = tokio::sync::watch::channel(false);
        let _ = STOP.set(tx);
        let handle = service_control_handler::register("rvpn-client", |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                STOP.get().unwrap().send_replace(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        let _ = STATUS.set(handle);
        handle.set_service_status(service_status(
            ServiceState::StartPending,
            ServiceExitCode::Win32(0),
        ))?;
        let result = (|| {
            let mut args = crate::Args::parse();
            args.command = None;
            tokio::runtime::Runtime::new()?.block_on(crate::async_main(args))
        })();
        let success = result
            .as_ref()
            .is_ok_and(|code| *code == std::process::ExitCode::SUCCESS);
        handle.set_service_status(service_status(
            ServiceState::Stopped,
            ServiceExitCode::Win32(if success { 0 } else { 1 }),
        ))?;
        result.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn command_failure_keeps_stdout_stderr_and_exit_code() {
        #[cfg(windows)]
        let error = output(
            "cmd.exe",
            &[
                "/C",
                "echo detailed stdout & echo detailed stderr 1>&2 & exit /b 7",
            ],
        )
        .unwrap_err();
        #[cfg(unix)]
        let error = output(
            "sh",
            &[
                "-c",
                "echo 'detailed stdout'; echo 'detailed stderr' >&2; exit 7",
            ],
        )
        .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("detailed stdout"));
        assert!(text.contains("detailed stderr"));
        assert!(text.contains('7'));
    }

    #[test]
    fn startup_report_ignores_other_processes_and_preserves_actual_url_and_error() {
        let temp = tempfile::tempdir().unwrap();
        assert!(read_startup(temp.path(), 42).unwrap().is_none());
        let report = StartupReport {
            pid: 42,
            webui: Some("http://[::1]:54321/".into()),
            error: Some("VPN 启动失败：invalid key".into()),
            dns_warning: None,
        };
        std::fs::write(
            temp.path().join("service-startup.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        assert!(read_startup(temp.path(), 43).unwrap().is_none());
        let report = read_startup(temp.path(), 42).unwrap().unwrap();
        assert_eq!(report.webui.as_deref(), Some("http://[::1]:54321/"));
        assert_eq!(report.error.as_deref(), Some("VPN 启动失败：invalid key"));
    }

    #[test]
    fn macos_sudo_preserves_arguments_and_elevates_only_service_mutations() {
        let exe = Path::new("/opt/r vpn/rvpn");
        let config = Path::new("/tmp/a $vpn's 配置.toml");
        let action = privileged_action(&ServiceAction::Install).unwrap();
        let command = macos_elevation_command(exe, config, action);
        assert_eq!(command.get_program(), "/usr/bin/sudo");
        assert_eq!(command.get_args().collect::<Vec<_>>(), [
            std::ffi::OsStr::new("--"), exe.as_os_str(), std::ffi::OsStr::new("--config"),
            config.as_os_str(), std::ffi::OsStr::new("service"), std::ffi::OsStr::new("install"),
        ]);
        assert!(privileged_action(&ServiceAction::Status).is_none());
        assert!(privileged_action(&ServiceAction::Run { working_directory: PathBuf::new() }).is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn foreground_authorization_requires_a_valid_system_dns_opt_in() {
        let mut config = crate::config::ClientConfig::default();
        assert!(!foreground_requests_admin(&config));
        config.dns_proxy.enabled = true;
        config.dns_proxy.listen_address = "127.0.0.1:53".into();
        assert!(!foreground_requests_admin(&config));
        config.dns_proxy.takeover_system_dns = true;
        assert!(foreground_requests_admin(&config));
        config.dns_proxy.nameservers = vec!["127.0.0.1:53".into()];
        assert!(!foreground_requests_admin(&config));
        config.dns_proxy.nameservers = vec!["https://223.6.6.6/dns-query".into()];
        config.tun.enabled = true;
        assert!(!foreground_requests_admin(&config));

        let exe = Path::new("/opt/r vpn/rvpn");
        let mut command = macos_sudo(exe, true);
        command.args(["-c", "config with spaces.toml", "-vv"]);
        assert_eq!(command.get_args().collect::<Vec<_>>(), [
            std::ffi::OsStr::new("-n"), std::ffi::OsStr::new("--"), exe.as_os_str(),
            std::ffi::OsStr::new("-c"), std::ffi::OsStr::new("config with spaces.toml"),
            std::ffi::OsStr::new("-vv"),
        ]);
    }

    #[test]
    fn service_cli_and_dns_config_are_backwards_compatible() {
        for action in ["install", "uninstall", "start", "stop", "status"] {
            let args =
                crate::Args::try_parse_from(["rvpn", "--config", "custom.toml", "service", action])
                    .unwrap();
            assert_eq!(args.config, PathBuf::from("custom.toml"));
            assert!(matches!(
                args.command,
                Some(crate::Commands::Service { .. })
            ));
        }
        let old: crate::config::ClientConfig = toml::from_str("").unwrap();
        assert!(!old.dns_proxy.nameservers.is_empty());
        let config: crate::config::ClientConfig = toml::from_str("[dns_proxy]\nenabled = true\nnameservers = ['https://1.1.1.1/dns-query', '223.5.5.5:53']\n").unwrap();
        assert!(
            rvpn_split_tunnel::dns_cache::DnsUpstreams::new(&config.dns_proxy.nameservers).is_ok()
        );
    }

    #[test]
    fn service_definitions_escape_paths() {
        let text = unit("/opt/my vpn/rvpn", "/tmp/a%$\".toml", "/opt/my vpn %\\ ");
        assert!(text
            .lines()
            .any(|line| line == "WorkingDirectory=/opt/my vpn %%\\ /"));
        assert!(text.contains("ExecStart=\"/opt/my vpn/rvpn\" --config \"/tmp/a%%$$\\\".toml\""));
        assert!(unit("/bin/rvpn", "/client.toml", "/")
            .lines()
            .any(|line| line == "WorkingDirectory=/"));
        assert!(plist("/a&b", "/c<d", "/e").contains("<string>/a&amp;b</string>"));
        let config = "/配置/my vpn -- a%$\"&<.toml";
        for definition in [
            unit("/bin/rvpn", config, "/"),
            plist("/bin/rvpn", config, "/"),
        ] {
            assert_eq!(
                definition_config(&definition).unwrap(),
                Some(PathBuf::from(config))
            );
            assert!(definition.contains("RVPN_SYSTEM_SERVICE"));
            let legacy = definition
                .lines()
                .filter(|line| !line.contains("rvpn-config:"))
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(
                definition_config(&legacy).unwrap(),
                Some(PathBuf::from(config))
            );
        }
    }
}
