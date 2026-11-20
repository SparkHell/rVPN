//! Per-link unicast servers used by clients of systemd-resolved's native API.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, process::Command};

const LOCAL: [&str; 2] = ["127.0.0.1", "::1"];

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    boot_id: String,
    links: BTreeMap<u32, Link>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Link {
    name: String,
    servers: Vec<String>,
}

fn resolvectl(args: &[&str]) -> Result<String> {
    let output = Command::new("/usr/bin/resolvectl")
        .args(["--no-pager", "--"])
        .args(args)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .output()
        .context("系统正在使用 systemd-resolved，需要 resolvectl 管理链路 DNS")?;
    ensure!(
        output.status.success(),
        "resolvectl: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn links(output: &str) -> Result<BTreeMap<u32, Link>> {
    let mut links = BTreeMap::new();
    let mut current: Option<&mut Link> = None;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        if line.starts_with("Global:") {
            current = None;
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            if let Some(link) = &mut current {
                link.servers
                    .extend(line.split_whitespace().map(str::to_owned));
            }
            continue;
        }
        let (index, rest) = line
            .strip_prefix("Link ")
            .and_then(|s| s.split_once(" ("))
            .context("Unexpected resolvectl dns output")?;
        let (name, servers) = rest
            .rsplit_once("):")
            .context("Missing resolvectl link name")?;
        let link = Link {
            name: name.to_owned(),
            servers: servers.split_whitespace().map(str::to_owned).collect(),
        };
        current = Some(links.entry(index.parse()?).or_insert(link));
    }
    Ok(links)
}

impl Snapshot {
    pub(crate) fn capture() -> Result<Option<Self>> {
        if !Path::new("/run/systemd/resolve/io.systemd.Resolve").exists()
            && !Path::new("/run/systemd/resolve/stub-resolv.conf").exists()
        {
            return Ok(None);
        }
        let mut previous = links(&resolvectl(&["dns"])?)?;
        previous.retain(|_, link| !link.servers.is_empty() && link.servers != LOCAL);
        Ok(Some(Self {
            boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
            links: previous,
        }))
    }

    pub(crate) fn apply(&self) -> Result<()> {
        if self.links.is_empty() {
            return Ok(());
        }
        let current = links(&resolvectl(&["dns"])?)?;
        for (index, saved) in &self.links {
            ensure!(
                current
                    .get(index)
                    .is_some_and(|link| link.name == saved.name && link.servers == saved.servers),
                "链路 {} 的 DNS 在接管前已变化，请重试",
                saved.name
            );
            resolvectl(&["dns", &index.to_string(), LOCAL[0], LOCAL[1]])?;
        }
        let active = links(&resolvectl(&["dns"])?)?;
        for (index, saved) in &self.links {
            ensure!(
                active
                    .get(index)
                    .is_some_and(|link| link.name == saved.name && link.servers == LOCAL),
                "systemd-resolved 未应用链路 {} 的 DNS 设置",
                saved.name
            );
        }
        Ok(())
    }

    pub(crate) fn restore(&self) -> Result<()> {
        if self.links.is_empty()
            || std::fs::read_to_string("/proc/sys/kernel/random/boot_id")? != self.boot_id
        {
            return Ok(());
        }
        let active = links(&resolvectl(&["dns"])?)?;
        let mut errors = Vec::new();
        for (index, old) in &self.links {
            if active
                .get(index)
                .is_some_and(|link| link.name == old.name && link.servers == LOCAL)
            {
                let index = index.to_string();
                let mut args = vec!["dns", &index];
                args.extend(old.servers.iter().map(String::as_str));
                if let Err(error) = resolvectl(&args) {
                    errors.push(error.to_string());
                }
            }
        }
        ensure!(
            errors.is_empty(),
            "恢复 systemd-resolved DNS 失败：{}",
            errors.join(", ")
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_per_link_servers_with_ports_scopes_and_tls_names() {
        let list = links(
            "Global: 9.9.9.9\nLink 2 (eth0): 1.1.1.1#one.example\n  fe80::5%2\nLink 3 (wifi):\n",
        )
        .unwrap();
        assert_eq!(list[&2].servers, ["1.1.1.1#one.example", "fe80::5%2"]);
        assert!(list[&3].servers.is_empty());
        assert!(links("unexpected").is_err());
    }
}
