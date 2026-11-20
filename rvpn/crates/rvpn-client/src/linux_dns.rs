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

pub struct SystemDns {
    _lock: fslock::LockFile,
    resolver: PathBuf,
    backup: PathBuf,
}

impl SystemDns {
    pub fn install(address: std::net::SocketAddr, dual_stack: bool) -> Result<Option<Self>> {
        Self::install_at(
            address,
            dual_stack,
            Path::new(RESOLVER),
            Path::new(DNS_BACKUP),
            Path::new("/run/rvpn-tun-resolver.lock"),
            crate::resolved_dns::Snapshot::capture,
        )
    }

    fn install_at(
        address: std::net::SocketAddr,
        dual_stack: bool,
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
    let resolved = backup.join("resolved.json");
    if std::fs::symlink_metadata(resolver).is_ok_and(|m| m.is_file())
        && std::fs::read(resolver).is_ok_and(|bytes| bytes == active)
    {
        match std::fs::symlink_metadata(&original) {
            Ok(_) => std::fs::rename(&original, resolver)?,
            Err(e) if e.kind() == ErrorKind::NotFound => std::fs::remove_file(resolver)?,
            Err(e) => return Err(e.into()),
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
}
