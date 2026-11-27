//! Linux system resolver takeover shared by proxy and TUN modes.
use anyhow::{bail, ensure, Context, Result};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) fn recover() -> Result<()> {
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
const DEFAULT_FALLBACK_RESOLVER: &str = "# Fallback resolver written by rVPN (original /etc/resolv.conf was missing or broken)\nnameserver 223.5.5.5\nnameserver 1.1.1.1\n";

fn extract_fallback_ips(nameservers: &[String]) -> Vec<std::net::IpAddr> {
    let mut ips = Vec::new();
    for entry in nameservers {
        let trimmed = entry.trim();
        let host = if let Some(rest) = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
        {
            let authority = rest.split('/').next().unwrap_or_default();
            if let Some(bracketed) = authority.strip_prefix('[') {
                bracketed.split(']').next().unwrap_or_default()
            } else {
                authority.split(':').next().unwrap_or_default()
            }
        } else {
            trimmed
        };
        let ip = host
            .parse::<std::net::IpAddr>()
            .ok()
            .or_else(|| host.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()));
        if let Some(ip) = ip.filter(|ip| !ip.is_loopback() && !ip.is_unspecified()) {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips
}

fn build_fallback_resolver(nameservers: &[String], original_contents: Option<&str>) -> String {
    let ips = extract_fallback_ips(nameservers);
    let mut fallback = String::from(
        "# Fallback resolver written by rVPN (original /etc/resolv.conf was missing or broken)\n",
    );
    if ips.is_empty() {
        fallback.push_str("nameserver 223.5.5.5\nnameserver 1.1.1.1\n");
    } else {
        for ip in ips {
            fallback.push_str(&format!("nameserver {ip}\n"));
        }
    }
    if let Some(contents) = original_contents {
        for line in contents.lines() {
            if matches!(
                line.split_whitespace().next(),
                Some("search" | "domain" | "options")
            ) {
                fallback.push_str(line);
                fallback.push('\n');
            }
        }
    }
    fallback
}

fn original_is_usable(original: &Path, resolver: &Path) -> bool {
    match std::fs::symlink_metadata(original) {
        Ok(m) if m.is_file() => true,
        Ok(m) if m.is_symlink() => std::fs::read_link(original)
            .ok()
            .map(|target| {
                if target.is_absolute() {
                    target
                } else {
                    resolver.parent().unwrap_or_else(|| Path::new("/")).join(target)
                }
            })
            .is_some_and(|resolved| resolved.try_exists().unwrap_or(false)),
        _ => false,
    }
}

fn write_fallback_resolver(resolver: &Path, fallback_path: &Path) -> Result<()> {
    let content = std::fs::read(fallback_path)
        .ok()
        .filter(|bytes| !bytes.is_empty())
        .unwrap_or_else(|| DEFAULT_FALLBACK_RESOLVER.as_bytes().to_vec());
    let dir = resolver.parent().context("Missing resolver directory")?;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))?;
    file.write_all(&content)?;
    file.persist(resolver)?;
    Ok(())
}

pub struct SystemDns {
    _lock: fslock::LockFile,
    resolver: PathBuf,
    backup: PathBuf,
}

impl SystemDns {
    pub fn install(
        address: std::net::SocketAddr,
        dual_stack: bool,
        fallback_nameservers: &[String],
    ) -> Result<Option<Self>> {
        Self::install_at(
            address,
            dual_stack,
            fallback_nameservers,
            Path::new(RESOLVER),
            Path::new(DNS_BACKUP),
            Path::new("/run/rvpn-tun-resolver.lock"),
            crate::resolved_dns::Snapshot::capture,
        )
    }

    fn install_at(
        address: std::net::SocketAddr,
        dual_stack: bool,
        fallback_nameservers: &[String],
        resolver: &Path,
        backup_path: &Path,
        lock_path: &Path,
        capture: fn() -> Result<Option<crate::resolved_dns::Snapshot>>,
    ) -> Result<Option<Self>> {
        ensure!(
            address.port() == 53 && address.ip().is_loopback() && address.is_ipv4(),
            "System DNS requires a local IPv4 DNS proxy on port 53"
        );
        let dir = resolver.parent().context("Missing resolver directory")?;
        let contents = std::fs::read_to_string(resolver);
        if !dual_stack
            && contents.as_ref().is_ok_and(|s| {
                let mut servers = s.lines().filter_map(|line| {
                    let mut words = line.split_whitespace();
                    (words.next()? == "nameserver")
                        .then(|| words.next())
                        .flatten()
                });
                let ip = address.ip().to_string();
                servers.next() == Some(ip.as_str()) && servers.all(|server| server == ip)
            })
        {
            return Ok(None);
        }
        let mut lock = fslock::LockFile::open(lock_path)?;
        ensure!(
            lock.try_lock()?,
            "Another rVPN session is managing system DNS"
        );
        ensure!(
            !backup_path.try_exists()?,
            "Previous TUN resolver backup still exists"
        );
        let mut active = format!("# Managed by rVPN\nnameserver {}\n", address.ip());
        if dual_stack {
            active.push_str("nameserver ::1\n");
        }
        if let Ok(contents) = &contents {
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
        let fallback = build_fallback_resolver(fallback_nameservers, contents.as_deref().ok());
        // Publish the recovery files together before replacing the system resolver.
        let backup = tempfile::tempdir_in(dir)?;
        let resolved = if dual_stack { capture()? } else { None };
        if let Some(snapshot) = &resolved {
            std::fs::write(
                backup.path().join("resolved.json"),
                serde_json::to_vec(snapshot)?,
            )?;
        }
        match std::fs::symlink_metadata(resolver) {
            Ok(m) if m.is_symlink() || m.is_file() => {
                std::fs::hard_link(resolver, backup.path().join("original"))?
            }
            Ok(_) => bail!("Unsupported /etc/resolv.conf file type"),
            Err(e) if e.kind() == ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        std::fs::write(backup.path().join("active"), &active)?;
        std::fs::write(backup.path().join("fallback"), &fallback)?;
        let mut file = tempfile::NamedTempFile::new_in(dir)?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
        file.write_all(active.as_bytes())?;
        std::fs::rename(backup.path(), backup_path)?;
        let guard = Self {
            _lock: lock,
            resolver: resolver.to_owned(),
            backup: backup_path.to_owned(),
        };
        file.persist(resolver)?;
        if let Some(snapshot) = resolved {
            snapshot.apply()?;
        }
        Ok(Some(guard))
    }
}

fn restore_resolver() -> Result<()> {
    restore_resolver_at(Path::new(RESOLVER), Path::new(DNS_BACKUP))
}

fn restore_resolver_at(resolver: &Path, backup: &Path) -> Result<()> {
    if !backup.try_exists()? {
        return Ok(());
    }
    let active = std::fs::read(backup.join("active"))?;
    let original = backup.join("original");
    let fallback = backup.join("fallback");
    let resolved = backup.join("resolved.json");
    if std::fs::symlink_metadata(resolver).is_ok_and(|m| m.is_file())
        && std::fs::read(resolver).is_ok_and(|bytes| bytes == active)
    {
        if original_is_usable(&original, resolver) {
            std::fs::rename(&original, resolver)?;
        } else {
            tracing::warn!(
                "Original {} is missing or a dangling symlink; writing fallback resolver",
                resolver.display()
            );
            write_fallback_resolver(resolver, &fallback)?;
        }
    }
    if resolved.try_exists()? {
        let snapshot: crate::resolved_dns::Snapshot =
            serde_json::from_slice(&std::fs::read(resolved)?)?;
        snapshot.restore()?;
    }
    if std::fs::symlink_metadata(&original).is_ok() {
        std::fs::remove_file(original)?;
    }
    // Rename before cleanup so an interrupted cleanup never looks like a valid journal.
    let discarded = tempfile::tempdir_in(backup.parent().context("Missing backup directory")?)?;
    std::fs::rename(backup, discarded.path().join("done"))?;
    discarded.close()?;
    Ok(())
}

impl Drop for SystemDns {
    fn drop(&mut self) {
        if let Err(error) = restore_resolver_at(&self.resolver, &self.backup) {
            tracing::error!(%error, "Failed to restore system DNS");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_dns_restores_resolver_symlink_after_dual_stack_takeover() {
        let temp = tempfile::tempdir().unwrap();
        let resolver = temp.path().join("resolv.conf");
        let original = temp.path().join("provider.conf");
        let previous = "nameserver 192.0.2.1\nsearch office.example\noptions rotate\n";
        std::fs::write(&original, previous).unwrap();
        std::os::unix::fs::symlink(&original, &resolver).unwrap();
        let guard = SystemDns::install_at(
            "127.0.0.1:53".parse().unwrap(),
            true,
            &[],
            &resolver,
            &temp.path().join("backup"),
            &temp.path().join("lock"),
            || Ok(None),
        )
        .unwrap()
        .unwrap();
        let active = std::fs::read_to_string(&resolver).unwrap();
        assert!(active.contains(
            "nameserver 127.0.0.1\nnameserver ::1\nsearch office.example\noptions rotate\n"
        ));
        drop(guard);
        assert_eq!(std::fs::read_link(&resolver).unwrap(), original);
        assert_eq!(std::fs::read_to_string(&resolver).unwrap(), previous);
    }

    #[test]
    fn system_dns_restores_relative_symlink_when_target_exists() {
        let temp = tempfile::tempdir().unwrap();
        let etc = temp.path().join("etc");
        let run = temp.path().join("run");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        let resolver = etc.join("resolv.conf");
        let target = run.join("stub-resolv.conf");
        std::fs::write(&target, "nameserver 127.0.0.53\n").unwrap();
        std::os::unix::fs::symlink("../run/stub-resolv.conf", &resolver).unwrap();
        let guard = SystemDns::install_at(
            "127.0.0.1:53".parse().unwrap(),
            true,
            &[],
            &resolver,
            &etc.join(".rvpn-tun-dns"),
            &temp.path().join("lock"),
            || Ok(None),
        )
        .unwrap()
        .unwrap();
        drop(guard);
        assert_eq!(
            std::fs::read_link(&resolver).unwrap(),
            PathBuf::from("../run/stub-resolv.conf")
        );
        assert_eq!(
            std::fs::read_to_string(&resolver).unwrap(),
            "nameserver 127.0.0.53\n"
        );
    }

    #[test]
    fn system_dns_writes_fallback_when_original_is_dangling_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let resolver = temp.path().join("resolv.conf");
        let missing = temp.path().join("missing-stub-resolv.conf");
        std::os::unix::fs::symlink(&missing, &resolver).unwrap();
        let fallback_servers = vec![
            "https://223.6.6.6/dns-query".to_string(),
            "223.5.5.5:53".to_string(),
        ];
        let guard = SystemDns::install_at(
            "127.0.0.1:53".parse().unwrap(),
            true,
            &fallback_servers,
            &resolver,
            &temp.path().join("backup"),
            &temp.path().join("lock"),
            || Ok(None),
        )
        .unwrap()
        .unwrap();
        drop(guard);
        assert!(std::fs::symlink_metadata(&resolver).unwrap().is_file());
        let restored = std::fs::read_to_string(&resolver).unwrap();
        assert!(restored.contains("nameserver 223.6.6.6\nnameserver 223.5.5.5\n"));
    }

    #[test]
    fn system_dns_writes_fallback_when_original_was_missing() {
        let temp = tempfile::tempdir().unwrap();
        let resolver = temp.path().join("resolv.conf");
        let guard = SystemDns::install_at(
            "127.0.0.1:53".parse().unwrap(),
            true,
            &[],
            &resolver,
            &temp.path().join("backup"),
            &temp.path().join("lock"),
            || Ok(None),
        )
        .unwrap()
        .unwrap();
        drop(guard);
        assert!(std::fs::symlink_metadata(&resolver).unwrap().is_file());
        let restored = std::fs::read_to_string(&resolver).unwrap();
        assert!(restored.contains("nameserver 223.5.5.5\nnameserver 1.1.1.1\n"));
    }
}
