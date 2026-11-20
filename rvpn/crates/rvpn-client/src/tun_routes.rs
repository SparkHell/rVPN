//! Linux policy routes owned by one TUN session.
use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use ip_network::IpNetwork;
use rvpn_split_tunnel::RoutingDecision;

const TABLE: &str = "25381";
const PRIORITY: &str = "10000";
const LAN: [&str; 5] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
];

fn ip(args: &[&str]) -> Result<String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .context("Run iproute2")?;
    ensure!(
        output.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?)
}

pub fn private(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast()
}

fn covers(outer: IpNetwork, inner: IpNetwork) -> bool {
    outer.netmask() <= inner.netmask() && outer.contains(inner.network_address())
}

fn preferred_route(
    decisions: impl Iterator<Item = RoutingDecision> + Clone,
) -> Option<RoutingDecision> {
    [
        RoutingDecision::Block,
        RoutingDecision::Tunnel,
        RoutingDecision::Bypass,
    ]
    .into_iter()
    .find(|decision| decisions.clone().any(|route| route == *decision))
}

struct State {
    endpoints: HashSet<Ipv4Addr>,
    leases: HashMap<Ipv4Addr, HashMap<String, (RoutingDecision, Instant)>>,
    installed: HashMap<Ipv4Addr, RoutingDecision>,
}

pub struct Routes {
    device: String,
    selected: Vec<IpNetwork>,
    direct: Vec<IpNetwork>,
    forced: Vec<IpNetwork>,
    full_unknown: bool,
    active: bool,
    marker: PathBuf,
    _lock: fslock::LockFile,
    state: Mutex<State>,
}

impl Routes {
    pub fn new(
        device: &str,
        routes: &[String],
        direct: Vec<IpNetwork>,
        forced: Vec<IpNetwork>,
        full_unknown: bool,
    ) -> Result<Self> {
        let selected: Vec<IpNetwork> = routes
            .iter()
            .map(|route| route.parse())
            .collect::<Result<_, _>>()?;
        ensure!(
            !selected.is_empty()
                && selected
                    .iter()
                    .all(|network| matches!(network, IpNetwork::V4(_))),
            "Desktop TUN requires at least one IPv4 route; IPv6 TUN is unavailable"
        );
        ensure!(
            device
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
            "Unsupported TUN interface name"
        );
        let mut lock = fslock::LockFile::open("/run/rvpn-tun-routes.lock")?;
        ensure!(
            lock.try_lock()?,
            "Another rVPN session is managing TUN routes"
        );
        let rules = ip(&["-4", "rule", "show"])?;
        ensure!(
            !rules
                .lines()
                .any(|line| line.starts_with(&format!("{PRIORITY}:"))
                    || line.split_whitespace().any(|word| word == TABLE)),
            "TUN routing table or priority already in use"
        );
        let existing = Command::new("ip")
            .args(["-4", "route", "show", "table", TABLE])
            .output()?;
        ensure!(
            existing.stdout.is_empty(),
            "TUN routing table already contains routes"
        );
        let marker = route_marker()?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)?;
        Ok(Self {
            marker,
            device: device.into(),
            selected,
            direct,
            forced,
            full_unknown,
            active: false,
            _lock: lock,
            state: Mutex::new(State {
                endpoints: HashSet::new(),
                leases: HashMap::new(),
                installed: HashMap::new(),
            }),
        })
    }

    pub fn activate(&mut self) -> Result<()> {
        // A dedicated table lets the kernel retain the original routes and lets
        // teardown delete only rVPN-owned state. A throw falls through to main.
        let mut routes = String::new();
        let lan: Vec<IpNetwork> = LAN.iter().map(|cidr| cidr.parse().unwrap()).collect();
        if self.full_unknown {
            for scope in &self.selected {
                if lan.iter().any(|network| covers(*network, *scope)) {
                    continue;
                }
                routes.push_str(&format!(
                    "route replace {scope} dev {} table {TABLE}\n",
                    self.device
                ));
            }
        }
        for bypass in &self.direct {
            if !self.forced.iter().any(|forced| covers(*forced, *bypass)) {
                routes.push_str(&format!("route replace throw {bypass} table {TABLE}\n"));
            }
        }
        for forced in &self.forced {
            for scope in &self.selected {
                let route = if covers(*scope, *forced) {
                    *forced
                } else if covers(*forced, *scope) {
                    *scope
                } else {
                    continue;
                };
                if lan.iter().any(|network| covers(*network, route)) {
                    continue;
                }
                routes.push_str(&format!(
                    "route replace {route} dev {} table {TABLE}\n",
                    self.device
                ));
            }
        }
        for lan in lan {
            // Protect these even when an operator supplies a force-tunnel rule.
            routes.push_str(&format!("route replace throw {lan} table {TABLE}\n"));
        }
        let state = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        for address in &state.endpoints {
            routes.push_str(&format!("route replace throw {address}/32 table {TABLE}\n"));
        }
        if !routes.is_empty() {
            let mut child = Command::new("ip")
                .args(["-4", "-batch", "-"])
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let write = child
                .stdin
                .take()
                .context("Open ip batch input")?
                .write_all(routes.as_bytes());
            let output = child.wait_with_output()?;
            ensure!(
                output.status.success(),
                "Install TUN routes: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            write?;
        }
        ip(&["-4", "rule", "add", "priority", PRIORITY, "lookup", TABLE])?;
        self.active = true;
        Ok(())
    }

    pub fn pin(&self, address: IpAddr) -> Result<()> {
        let IpAddr::V4(address) = address else {
            return Ok(());
        };
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !state.endpoints.contains(&address) {
            self.replace(address, RoutingDecision::Bypass)?;
            state.endpoints.insert(address);
        }
        Ok(())
    }

    pub fn remember(
        &self,
        host: &str,
        ips: &[IpAddr],
        decision: RoutingDecision,
        ttl: Duration,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for &address in ips {
            let IpAddr::V4(address) = address else {
                continue;
            };
            if private(address)
                || state.endpoints.contains(&address)
                || !self.selected.iter().any(|range| range.contains(address))
            {
                continue;
            }
            ensure!(
                state.leases.len() < 4096 || state.leases.contains_key(&address),
                "TUN DNS route cache is full"
            );
            let leases = state.leases.entry(address).or_default();
            ensure!(
                leases.len() < 64 || leases.contains_key(host),
                "Too many DNS names share {address}"
            );
            leases.insert(host.to_ascii_lowercase(), (decision, Instant::now() + ttl));
            self.refresh(&mut state, address)?;
        }
        Ok(())
    }

    fn replace(&self, address: Ipv4Addr, decision: RoutingDecision) -> Result<()> {
        let host = format!("{address}/32");
        match decision {
            RoutingDecision::Tunnel => ip(&[
                "-4",
                "route",
                "replace",
                &host,
                "dev",
                &self.device,
                "table",
                TABLE,
            ])?,
            RoutingDecision::Bypass => {
                ip(&["-4", "route", "replace", "throw", &host, "table", TABLE])?
            }
            RoutingDecision::Block => {
                ip(&["-4", "route", "replace", "prohibit", &host, "table", TABLE])?
            }
        };
        Ok(())
    }

    fn refresh(&self, state: &mut State, address: Ipv4Addr) -> Result<()> {
        let leases = state
            .leases
            .get_mut(&address)
            .context("Missing DNS route lease")?;
        leases.retain(|_, (_, expires)| *expires > Instant::now());
        if state.endpoints.contains(&address) {
            state.installed.remove(&address);
        } else if let Some(decision) = preferred_route(leases.values().map(|(route, _)| *route)) {
            if state.installed.get(&address) != Some(&decision) {
                self.replace(address, decision)?;
                state.installed.insert(address, decision);
            }
        } else if state.installed.contains_key(&address) {
            let host: IpNetwork = format!("{address}/32").parse()?;
            let covered_by_force = self.forced.iter().any(|net| net.contains(address));
            if self.forced.contains(&host) || (self.selected.contains(&host) && covered_by_force) {
                self.replace(address, RoutingDecision::Tunnel)?;
            } else if self.direct.contains(&host) && !covered_by_force {
                self.replace(address, RoutingDecision::Bypass)?;
            } else if self.full_unknown && self.selected.contains(&host) {
                self.replace(address, RoutingDecision::Tunnel)?;
            } else {
                ip(&["-4", "route", "del", &host.to_string(), "table", TABLE])?;
            }
            state.installed.remove(&address);
        }
        if leases.is_empty() {
            state.leases.remove(&address);
        }
        Ok(())
    }

    pub async fn expire(&self) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let expired: Vec<_> = state
                .leases
                .iter()
                .filter_map(|(ip, leases)| {
                    leases
                        .values()
                        .any(|(_, expiry)| *expiry <= Instant::now())
                        .then_some(*ip)
                })
                .collect();
            for address in expired {
                self.refresh(&mut state, address)?;
            }
        }
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        if self.active {
            if let Err(error) = ip(&["-4", "rule", "del", "priority", PRIORITY, "lookup", TABLE]) {
                tracing::error!(%error, "Failed to restore routing policy");
            }
        }
        if ip(&["-4", "route", "flush", "table", TABLE]).is_ok()
            && ip(&["-4", "rule", "show"]).is_ok_and(|rules| !owns_rule(&rules))
        {
            let _ = std::fs::remove_file(&self.marker);
        }
    }
}

fn route_marker() -> Result<PathBuf> {
    let namespace = std::fs::metadata("/proc/self/ns/net")?.ino();
    Ok(PathBuf::from(format!(
        "/run/rvpn-tun-{namespace}-{TABLE}.owned"
    )))
}

fn owns_rule(rules: &str) -> bool {
    rules.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.next() == Some("10000:") && words.eq(["from", "all", "lookup", TABLE])
    })
}

/// Recover owned state from an interrupted session before starting either network mode.
pub fn recover() -> Result<()> {
    let marker = route_marker()?;
    if marker.try_exists()? {
        let mut lock = fslock::LockFile::open("/run/rvpn-tun-routes.lock")?;
        if lock.try_lock()? && marker.try_exists()? {
            if owns_rule(&ip(&["-4", "rule", "show"])?) {
                ip(&["-4", "rule", "del", "priority", PRIORITY, "lookup", TABLE])?;
            }
            // A closed TUN device can already have removed the last table entry.
            if !Command::new("ip")
                .args(["-4", "route", "show", "table", TABLE])
                .output()?
                .stdout
                .is_empty()
            {
                ip(&["-4", "route", "flush", "table", TABLE])?;
            }
            std::fs::remove_file(marker)?;
        }
    }
    if Path::new(DNS_BACKUP).try_exists()? {
        let mut lock = fslock::LockFile::open("/run/rvpn-tun-resolver.lock")?;
        if lock.try_lock()? {
            restore_resolver()?;
        }
    }
    Ok(())
}

const DNS_BACKUP: &str = "/etc/.rvpn-tun-dns";
const RESOLVER: &str = "/etc/resolv.conf";

pub struct SystemDns {
    _lock: fslock::LockFile,
}

impl SystemDns {
    pub fn install(address: std::net::SocketAddr) -> Result<Option<Self>> {
        ensure!(
            address.port() == 53 && address.ip().is_loopback() && address.is_ipv4(),
            "Linux TUN DNS requires a local IPv4 DNS proxy on port 53"
        );
        let resolver = Path::new(RESOLVER);
        let contents = std::fs::read_to_string(resolver);
        if contents.as_ref().is_ok_and(|s| {
            let mut servers = s.lines().filter_map(|line| {
                let mut words = line.split_whitespace();
                (words.next()? == "nameserver")
                    .then(|| words.next())
                    .flatten()
            });
            let ip = address.ip().to_string();
            servers.next() == Some(ip.as_str()) && servers.all(|server| server == ip)
        }) {
            return Ok(None);
        }
        let mut lock = fslock::LockFile::open("/run/rvpn-tun-resolver.lock")?;
        ensure!(
            lock.try_lock()?,
            "Another rVPN session is managing system DNS"
        );
        ensure!(
            !Path::new(DNS_BACKUP).try_exists()?,
            "Previous TUN resolver backup still exists"
        );
        let mut active = format!("# Managed by rVPN TUN\nnameserver {}\n", address.ip());
        if let Ok(contents) = contents {
            for line in contents.lines() {
                if matches!(
                    line.split_whitespace().next(),
                    Some("search" | "domain" | "options")
                ) {
                    active.push_str(line);
                    active.push('\n');
                }
            }
        }
        // Publish the recovery files together before replacing the system resolver.
        let backup = tempfile::tempdir_in("/etc")?;
        match std::fs::symlink_metadata(resolver) {
            Ok(m) if m.is_symlink() || m.is_file() => {
                std::fs::hard_link(resolver, backup.path().join("original"))?
            }
            Ok(_) => bail!("Unsupported /etc/resolv.conf file type"),
            Err(e) if e.kind() == ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        std::fs::write(backup.path().join("active"), &active)?;
        let mut file = tempfile::NamedTempFile::new_in("/etc")?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
        file.write_all(active.as_bytes())?;
        std::fs::rename(backup.path(), DNS_BACKUP)?;
        let guard = Self { _lock: lock };
        file.persist(resolver)?;
        Ok(Some(guard))
    }
}

fn restore_resolver() -> Result<()> {
    let backup = Path::new(DNS_BACKUP);
    if !backup.try_exists()? {
        return Ok(());
    }
    let active = std::fs::read(backup.join("active"))?;
    let original = backup.join("original");
    if std::fs::symlink_metadata(RESOLVER).is_ok_and(|m| m.is_file())
        && std::fs::read(RESOLVER).is_ok_and(|bytes| bytes == active)
    {
        match std::fs::symlink_metadata(&original) {
            Ok(_) => std::fs::rename(&original, RESOLVER)?,
            Err(e) if e.kind() == ErrorKind::NotFound => std::fs::remove_file(RESOLVER)?,
            Err(e) => return Err(e.into()),
        }
    }
    if std::fs::symlink_metadata(&original).is_ok() {
        std::fs::remove_file(original)?;
    }
    // Rename before cleanup so an interrupted cleanup never looks like a valid journal.
    let discarded = tempfile::tempdir_in("/etc")?;
    std::fs::rename(backup, discarded.path().join("done"))?;
    discarded.close()?;
    Ok(())
}

impl Drop for SystemDns {
    fn drop(&mut self) {
        if let Err(error) = restore_resolver() {
            tracing::error!(%error, "Failed to restore system DNS");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_routes_are_not_conflated_with_public_172_addresses() {
        for address in ["10.8.0.1", "172.16.0.1", "172.31.254.1", "192.168.1.1"] {
            assert!(private(address.parse().unwrap()));
        }
        for address in ["172.15.0.1", "172.32.0.1", "192.169.1.1"] {
            assert!(!private(address.parse().unwrap()));
        }
        let lan: IpNetwork = "172.16.0.0/12".parse().unwrap();
        assert!(covers(lan, "172.20.0.0/16".parse().unwrap()));
        assert!(!covers(lan, "172.0.0.0/8".parse().unwrap()));
    }

    #[test]
    fn shared_dns_address_prefers_tunnel_over_direct() {
        use RoutingDecision::*;
        assert_eq!(preferred_route([Bypass, Tunnel].into_iter()), Some(Tunnel));
        assert_eq!(
            preferred_route([Tunnel, Bypass, Block].into_iter()),
            Some(Block)
        );
        assert_eq!(preferred_route([Bypass].into_iter()), Some(Bypass));
        assert_eq!(preferred_route(std::iter::empty()), None);
    }
}
