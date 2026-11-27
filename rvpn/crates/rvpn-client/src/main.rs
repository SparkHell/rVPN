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

use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser;

use rvpn_client::{async_main, config, server_link, service, Args, Commands};

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
