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

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser;
use tracing::{error, info};

use rvpn_client::{
    config, control_panel, runtime_control, server_link, service, stats, Args, Commands,
};
use config::ClientConfig;

// Use mimalloc as the global allocator: glibc malloc arenas retain memory
// indefinitely under this client's allocation churn (a long-running Linux
// install grew to 850 MB RSS in a week; capping MALLOC_ARENA_MAX=2 pinned the
// same workload at ~27 MB, proving arena retention rather than a real leak).
// Disable with --no-default-features to build with the system allocator.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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

fn check_format(path: &std::path::Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(path.extension().and_then(|ext| ext.to_str()), Some("toml" | "json")),
        "Configuration file must have a .toml or .json extension: {}",
        path.display()
    );
    Ok(())
}

fn create_initial_config(path: &std::path::Path) -> anyhow::Result<()> {
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
    use stats::StatsHistory;

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
