//! Apply manual DNS overrides to the primary IPv4 and IPv6 network services.
use std::{
    io::Write,
    net::IpAddr,
    process::{Command, Stdio},
};

use anyhow::{ensure, Context, Result};

const LOCAL: [&str; 2] = ["127.0.0.1", "::1"];
type NetworkSetup = fn(&[&str]) -> Result<String>;

pub(crate) struct SystemDns {
    networksetup: NetworkSetup,
    changed: Vec<(String, Vec<String>)>,
}

impl SystemDns {
    pub(crate) fn take_over() -> Result<Self> {
        Self::apply(primary_services(scutil_show)?, networksetup)
    }

    fn apply(services: Vec<String>, networksetup: NetworkSetup) -> Result<Self> {
        let mut guard = Self {
            networksetup,
            changed: Vec::new(),
        };
        for service in services {
            let original = guard.servers(&service)?;
            if original == LOCAL {
                continue;
            }
            networksetup(&["-setdnsservers", &service, LOCAL[0], LOCAL[1]])
                .with_context(|| format!("设置 {service} 的 DNS 失败，需要管理员权限"))?;
            guard.changed.push((service.clone(), original));
            ensure!(
                guard.servers(&service)? == LOCAL,
                "{service} 的 DNS 设置未生效"
            );
        }
        Ok(guard)
    }

    fn servers(&self, service: &str) -> Result<Vec<String>> {
        let result = (self.networksetup)(&["-getdnsservers", service])?;
        if result.trim() == format!("There aren't any DNS Servers set on {service}.") {
            return Ok(Vec::new());
        }
        let servers: Vec<_> = result
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        ensure!(
            !servers.is_empty()
                && servers.iter().all(|s| s
                    .split('%')
                    .next()
                    .is_some_and(|ip| ip.parse::<IpAddr>().is_ok())),
            "无法读取 {service} 的原始 DNS 设置"
        );
        Ok(servers)
    }
}

impl Drop for SystemDns {
    fn drop(&mut self) {
        while let Some((service, original)) = self.changed.pop() {
            let restore = || -> Result<()> {
                if self.servers(&service)? == LOCAL {
                    let mut args = vec!["-setdnsservers", &service];
                    if original.is_empty() {
                        args.push("Empty");
                    } else {
                        args.extend(original.iter().map(String::as_str));
                    }
                    (self.networksetup)(&args)?;
                }
                Ok(())
            };
            if let Err(error) = restore() {
                tracing::error!("Failed to restore DNS on {service}: {error:#}");
            }
        }
    }
}

fn primary_services(show: fn(&str) -> Result<String>) -> Result<Vec<String>> {
    let mut services = Vec::new();
    for family in ["IPv4", "IPv6"] {
        let global = show(&format!("State:/Network/Global/{family}"))?;
        if let Some(id) = property(&global, "PrimaryService") {
            uuid::Uuid::parse_str(id).context("Invalid macOS primary service ID")?;
            let setup = show(&format!("Setup:/Network/Service/{id}"))?;
            let service = property(&setup, "UserDefinedName")
                .context("Missing macOS network service name")?;
            if !services.iter().any(|s| s == service) {
                services.push(service.to_owned());
            }
        }
    }
    ensure!(!services.is_empty(), "没有活动的 macOS 默认网络服务");
    Ok(services)
}

fn networksetup(args: &[&str]) -> Result<String> {
    output(
        Command::new("/usr/sbin/networksetup")
            .env("LC_ALL", "C")
            .args(args)
            .output()?,
    )
}

fn property<'a>(dictionary: &'a str, name: &str) -> Option<&'a str> {
    dictionary
        .lines()
        .filter_map(|line| line.trim().split_once(" : "))
        .find_map(|(key, value)| (key == name).then_some(value.trim()))
}

fn scutil_show(key: &str) -> Result<String> {
    let mut child = Command::new("/usr/sbin/scutil")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    writeln!(
        child.stdin.take().context("Missing scutil stdin")?,
        "show {key}"
    )?;
    output(child.wait_with_output()?)
}

fn output(result: std::process::Output) -> Result<String> {
    let stdout = String::from_utf8(result.stdout)?;
    ensure!(
        result.status.success() && !stdout.lines().any(|line| line.contains("** Error")),
        "macOS network configuration: {} {}",
        stdout.trim(),
        String::from_utf8_lossy(&result.stderr).trim()
    );
    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::BTreeMap};

    thread_local! {
        static SERVERS: RefCell<BTreeMap<String, Vec<String>>> = RefCell::default();
    }

    #[test]
    fn obtains_the_primary_service_from_each_available_family() {
        let services = primary_services(|key| {
            Ok(match key {
                "State:/Network/Global/IPv4" => {
                    " PrimaryService : 00000000-0000-0000-0000-000000000001"
                }
                "State:/Network/Global/IPv6" => {
                    " PrimaryService : 00000000-0000-0000-0000-000000000002"
                }
                "Setup:/Network/Service/00000000-0000-0000-0000-000000000001" => {
                    " UserDefinedName : Wi-Fi"
                }
                "Setup:/Network/Service/00000000-0000-0000-0000-000000000002" => {
                    " UserDefinedName : USB Ethernet"
                }
                _ => anyhow::bail!("unexpected key {key}"),
            }
            .into())
        })
        .unwrap();
        assert_eq!(services, ["Wi-Fi", "USB Ethernet"]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reads_native_primary_dns_settings_without_changing_services() {
        let services = primary_services(scutil_show).unwrap();
        let reader = SystemDns {
            networksetup,
            changed: Vec::new(),
        };
        for service in services {
            reader.servers(&service).unwrap();
        }
    }

    fn mock(args: &[&str]) -> Result<String> {
        let service = args[1];
        SERVERS.with_borrow_mut(|db| {
            let servers = db.entry(service.into()).or_default();
            match args[0] {
                "-getdnsservers" if servers.is_empty() => {
                    Ok(format!("There aren't any DNS Servers set on {service}."))
                }
                "-getdnsservers" => Ok(servers.join("\n")),
                "-setdnsservers" if service == "Unavailable" => {
                    anyhow::bail!("service went offline")
                }
                "-setdnsservers" => {
                    servers.clear();
                    if args[2] != "Empty" {
                        servers.extend(args[2..].iter().map(|s| s.to_string()));
                    }
                    Ok(String::new())
                }
                _ => unreachable!(),
            }
        })
    }

    #[test]
    fn restores_automatic_and_static_services_on_stop_or_partial_failure() {
        mock(&["-setdnsservers", "USB Ethernet", "9.9.9.9", "fe80::5%en0"]).unwrap();
        let services = vec!["Wi-Fi".into(), "USB Ethernet".into()];
        let guard = SystemDns::apply(services.clone(), mock).unwrap();
        assert_eq!(guard.servers("Wi-Fi").unwrap(), LOCAL);
        assert_eq!(guard.servers("USB Ethernet").unwrap(), LOCAL);
        drop(guard);
        let mut unavailable = services;
        unavailable.push("Unavailable".into());
        assert!(SystemDns::apply(unavailable, mock).is_err());
        assert!(mock(&["-getdnsservers", "Wi-Fi"])
            .unwrap()
            .starts_with("There aren't any"));
        assert_eq!(
            mock(&["-getdnsservers", "USB Ethernet"]).unwrap(),
            "9.9.9.9\nfe80::5%en0"
        );
    }
}
