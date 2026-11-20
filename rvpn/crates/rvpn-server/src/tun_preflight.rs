//! Check the server network namespace before assigning the TUN address.
use std::{net::Ipv4Addr, path::Path, process::Command};

use anyhow::{ensure, Context, Result};
use ip_network::Ipv4Network;
use serde::Deserialize;

use rvpn_server::config::TunNetworkConfig;

pub fn subnet(value: &str) -> Result<Ipv4Network> {
    let (addr, prefix) = value.split_once('/').unwrap_or((value, "32"));
    Ok(Ipv4Network::new_truncate(addr.parse()?, prefix.parse()?)?)
}

fn output(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let result = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Run {program}"))?;
    ensure!(
        result.status.success(),
        "{program} network inspection failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(result.stdout)
}

#[derive(Deserialize)]
struct Route {
    dst: Option<String>,
    dev: Option<String>,
    scope: Option<String>,
}

fn check_range(requested: Ipv4Network, existing: Ipv4Network, owner: &str) -> Result<()> {
    ensure!(
        !(requested.contains(existing.network_address())
            || existing.contains(requested.network_address())),
        "TUN subnet {requested} overlaps {existing} ({owner})"
    );
    Ok(())
}

pub fn has_connected_route(network: &str, device: &str) -> Result<bool> {
    let routes: Vec<Route> = serde_json::from_slice(&output(
        "ip",
        &[
            "-j", "-4", "route", "show", "table", "main", "exact", network,
        ],
    )?)?;
    Ok(!routes.is_empty()
        && routes
            .iter()
            .all(|r| r.dev.as_deref() == Some(device) && r.scope.as_deref() == Some("link")))
}

pub fn check(config: &TunNetworkConfig) -> Result<()> {
    let requested = subnet(&config.tun_ip)?;
    #[derive(Deserialize)]
    struct Interface {
        ifname: String,
        addr_info: Vec<Address>,
    }
    #[derive(Deserialize)]
    struct Address {
        local: Ipv4Addr,
        prefixlen: u8,
    }
    let interfaces: Vec<Interface> =
        serde_json::from_slice(&output("ip", &["-j", "-4", "addr", "show"])?)?;
    ensure!(
        !Path::new("/sys/class/net")
            .join(&config.interface_name)
            .exists(),
        "TUN interface name already in use: {}",
        config.interface_name
    );
    for iface in interfaces {
        for addr in iface.addr_info {
            check_range(
                requested,
                Ipv4Network::new_truncate(addr.local, addr.prefixlen)?,
                &iface.ifname,
            )?;
        }
    }
    let routes: Vec<Route> = serde_json::from_slice(&output(
        "ip",
        &["-j", "-4", "route", "show", "table", "all"],
    )?)?;
    for route in routes {
        match route.dst.as_deref() {
            None | Some("default" | "0.0.0.0/0") => (),
            Some(dst) => check_range(
                requested,
                subnet(dst)?,
                route.dev.as_deref().unwrap_or("routing table"),
            )?,
        }
    }
    // IPAM may reserve subnets even when no bridge route is visible yet.
    if Path::new("/var/run/docker.sock").try_exists()? {
        let socket = "unix:///var/run/docker.sock";
        let ids = String::from_utf8(output(
            "docker",
            &["--host", socket, "network", "ls", "-q"],
        )?)?;
        for id in ids.split_whitespace() {
            let networks: Vec<serde_json::Value> = serde_json::from_slice(&output(
                "docker",
                &["--host", socket, "network", "inspect", id],
            )?)?;
            for network in networks {
                let name = network["Name"]
                    .as_str()
                    .context("Missing Docker network name")?;
                if let Some(pools) = network["IPAM"]["Config"].as_array() {
                    for cidr in pools.iter().filter_map(|p| p["Subnet"].as_str()) {
                        if !cidr.contains(':') {
                            check_range(requested, subnet(cidr)?, &format!("Docker {name}"))?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlap_in_both_directions_and_adjacent_networks() {
        let requested = subnet("172.17.4.1/24").unwrap();
        for existing in [
            "172.17.0.0/16",
            "172.17.4.0/24",
            "172.17.4.128/25",
            "172.17.4.5",
        ] {
            assert!(check_range(requested, subnet(existing).unwrap(), "docker0").is_err());
        }
        check_range(requested, subnet("172.17.5.0/24").unwrap(), "docker0").unwrap();
    }
}
