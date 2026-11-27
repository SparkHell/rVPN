// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Multi-server routing pool.

//! Registry of named servers referenced by the multi-server router.
//!
//! Each entry holds the pre-parsed URL, TLS knobs, and the pre-loaded X3DH
//! prekey bundle so that per-flow dispatch is a cheap `HashMap` lookup —
//! no disk I/O or JSON parsing on the hot path. The client's identity key
//! is shared across all servers (SSH-model: one key, many hosts).

use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use crate::config::ExitStrategy;

use anyhow::{Context as _, Result};

use rvpn_core::crypto::X3DHPublicBundle;
use rvpn_tls::ResumptionStore;

use crate::config::{ClientConfig, ServerEntry, ServerIdentityConfig};

/// The reserved name for the top-level (implicit) server.
/// Defined in `rvpn-split-tunnel` (shared with the mobile crate); re-exported
/// here to keep existing `server_pool::DEFAULT_SERVER_NAME` paths working.
pub use rvpn_split_tunnel::DEFAULT_SERVER_NAME;

/// A resolved server, ready to be handed to `StreamRelay::connect`.
///
/// The `identity_config` is per-server so a pinned `[[server]].fingerprint`
/// can override the top-level TOFU/strict settings.
#[derive(Debug, Clone)]
pub struct ResolvedServer {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub sni_hostname: Option<String>,
    pub bundle: Arc<X3DHPublicBundle>,
    pub identity_config: ServerIdentityConfig,
    /// TLS session resumption store for this exit server. One store per exit,
    /// shared (via cheap `Clone`) by every connection this client makes to
    /// the server — pooled tunnel replacements, legacy per-flow relays,
    /// multiplexed reconnects — so reconnects resume the cached TLS 1.3
    /// ticket instead of paying a full handshake. Must outlive individual
    /// connections, which is why it lives here rather than per connection.
    pub resumption: ResumptionStore,
}

/// Registry of all servers keyed by name; `"default"` is always present.
#[derive(Debug, Clone)]
pub struct ServerPool {
    servers: HashMap<String, Arc<ResolvedServer>>,
    default_name: String,
    order: Vec<String>,
    strategy: ExitStrategy,
    cursor: Arc<AtomicUsize>,
}

impl ServerPool {
    /// Load and resolve every server declared in the config.
    ///
    /// The top-level `server_address` + `prekey_bundle` become the `"default"`
    /// entry; each `[[server]]` block adds another. Fails if any bundle can't
    /// be read, if names collide, or if a `[[server]]` uses the reserved
    /// name `"default"`.
    pub async fn from_config(config: &ClientConfig) -> Result<Self> {
        let mut servers: HashMap<String, Arc<ResolvedServer>> = HashMap::new();

        let default_bundle_path = config.prekey_bundle.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Prekey bundle file is required for the default server (set `prekey_bundle` in config)"
            )
        })?;
        let default_bundle = load_bundle(default_bundle_path).await?;
        let (host, port, path) = parse_server_url(&config.server_address);
        servers.insert(
            DEFAULT_SERVER_NAME.to_string(),
            Arc::new(ResolvedServer {
                name: DEFAULT_SERVER_NAME.to_string(),
                host,
                port,
                path,
                sni_hostname: config.sni_hostname.clone(),
                bundle: Arc::new(default_bundle),
                identity_config: config.server_identity.clone(),
                resumption: ResumptionStore::new(),
            }),
        );

        for entry in &config.extra_servers {
            let name = entry.name.trim().to_string();
            if name.is_empty() {
                anyhow::bail!("[[server]] entry has empty name");
            }
            if name == DEFAULT_SERVER_NAME {
                anyhow::bail!(
                    "[[server]] name '{}' is reserved; use a different symbolic name",
                    DEFAULT_SERVER_NAME
                );
            }
            if servers.contains_key(&name) {
                anyhow::bail!("Duplicate server name '{}'", name);
            }

            let (host, port, path) = parse_server_url(&entry.address);
            let bundle = load_bundle(&entry.prekey_bundle).await?;
            let identity_config = resolve_identity(&config.server_identity, entry);

            servers.insert(
                name.clone(),
                Arc::new(ResolvedServer {
                    name,
                    host,
                    port,
                    path,
                    sni_hostname: entry.sni_hostname.clone(),
                    bundle: Arc::new(bundle),
                    identity_config,
                    resumption: ResumptionStore::new(),
                }),
            );
        }

        Ok(Self {
            order: std::iter::once(DEFAULT_SERVER_NAME.to_owned())
                .chain(config.extra_servers.iter().map(|entry| entry.name.trim().to_owned()))
                .collect(),
            strategy: config.exit_strategy,
            cursor: Arc::new(AtomicUsize::new(0)),
            servers,
            default_name: DEFAULT_SERVER_NAME.to_string(),
        })
    }

    /// Return the resolved server for `name`, falling back to the default
    /// entry if the name is unknown. In practice the router only ever emits
    /// names present in the pool, but the fallback keeps the caller total.
    pub fn get_or_default(&self, name: &str) -> Arc<ResolvedServer> {
        self.servers
            .get(name)
            .or_else(|| self.servers.get(&self.default_name))
            .cloned()
            .expect("ServerPool always contains the default entry")
    }

    /// Try another exit only while establishing its transport. Once a target
    /// request has been sent it must never be replayed through a second exit.
    pub async fn connect_exit<T, F>(
        &self,
        routed: &str,
        mut connect: impl FnMut(Arc<ResolvedServer>) -> F,
    ) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>> + Send,
    {
        if self.order.len() == 1 || routed != DEFAULT_SERVER_NAME || matches!(self.strategy, ExitStrategy::Primary) {
            return connect(self.get_or_default(routed)).await;
        }
        let start = match self.strategy {
            ExitStrategy::RoundRobin => self.cursor.fetch_add(1, Ordering::Relaxed) % self.order.len(),
            _ => 0,
        };
        let mut last_error = None;
        for name in self.order[start..].iter().chain(&self.order[..start]) {
            // Leave time inside the proxy's 30s target deadline for other
            // exits and the destination acknowledgement.
            let attempt = tokio::time::timeout(
                std::time::Duration::from_secs(5), connect(self.get_or_default(name)),
            ).await.context("exit handshake timed out").and_then(|result| result);
            match attempt {
                Ok(connection) => return Ok(connection),
                Err(error) => {
                    tracing::warn!("Exit {name} unavailable: {error:#}");
                    last_error = Some(error.context(format!("exit {name}")));
                }
            }
        }
        Err(last_error.expect("pool always contains a primary exit"))
    }

    /// Names of every configured server, including `"default"`.
    pub fn names(&self) -> Vec<&str> {
        self.servers.keys().map(|s| s.as_str()).collect()
    }

    /// Number of extra (non-default) servers.
    pub fn extra_count(&self) -> usize {
        self.servers.len().saturating_sub(1)
    }

    /// Iterate over all resolved servers, including `"default"`.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<ResolvedServer>> {
        self.servers.values()
    }
}

async fn load_bundle(path: &std::path::Path) -> Result<X3DHPublicBundle> {
    let json = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read server prekey bundle: {}. Copy the public prekey-bundle.json generated by the server; the client cannot generate it", path.display()))?;
    serde_json::from_str(&json)
        .with_context(|| format!("Failed to parse prekey bundle: {:?}", path))
}

fn resolve_identity(
    base: &ServerIdentityConfig,
    entry: &ServerEntry,
) -> ServerIdentityConfig {
    let mut cfg = base.clone();
    if let Some(fp) = entry.fingerprint.clone() {
        cfg.fingerprint = Some(fp);
    }
    cfg
}

/// Parse a server URL into `(host, port, path)`. Mirrors the helper in
/// `main.rs` / `socks5.rs`; duplicated here to avoid pulling the caller
/// into this module's dependency graph.
pub(crate) fn parse_server_url(url: &str) -> (String, u16, String) {
    let url = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url);

    let (host_port, path) = url
        .split_once('/')
        .map(|(hp, p)| (hp, format!("/{}", p)))
        .unwrap_or((url, "/".to_string()));

    if host_port.starts_with('[') {
        if let Some(bracket_end) = host_port.find(']') {
            let host = host_port[1..bracket_end].to_string();
            let port = if bracket_end + 1 < host_port.len()
                && host_port.as_bytes()[bracket_end + 1] == b':'
            {
                host_port[bracket_end + 2..].parse().unwrap_or(443)
            } else {
                443
            };
            return (host, port, path);
        }
    }

    let (host, port) = host_port
        .split_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(443)))
        .unwrap_or_else(|| (host_port.to_string(), 443));

    (host, port, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_server_url_wss_with_path() {
        let (host, port, path) = parse_server_url("wss://example.com/api/v1/ws");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws");
    }

    #[test]
    fn parse_server_url_ipv6() {
        let (host, port, path) = parse_server_url("wss://[2001:db8::1]:8443/ws");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 8443);
        assert_eq!(path, "/ws");
    }

    fn test_server(name: &str) -> ResolvedServer {
        ResolvedServer {
            name: name.to_string(),
            host: "exit.example.com".to_string(),
            port: 443,
            path: "/api/v1/ws".to_string(),
            sni_hostname: None,
            bundle: Arc::new(X3DHPublicBundle {
                identity_key: [0xab; 32],
                identity_x25519_key: [0xcd; 32],
                signed_prekey: [0xef; 32],
                prekey_signature: [0x12; 64],
                one_time_prekey: None,
                identity_key_version: 1,
                rotation_signature: None,
            }),
            identity_config: ServerIdentityConfig::default(),
            resumption: ResumptionStore::new(),
        }
    }

    #[tokio::test]
    async fn exit_strategies_apply_only_to_unmatched_connections() {
        let names = [DEFAULT_SERVER_NAME, "backup"];
        let mut pool = ServerPool {
            servers: names.iter().map(|&name| (name.to_owned(), Arc::new(test_server(name)))).collect(),
            default_name: DEFAULT_SERVER_NAME.to_owned(),
            order: names.map(str::to_owned).to_vec(),
            strategy: ExitStrategy::RoundRobin,
            cursor: Arc::default(),
        };
        let success = |server: Arc<ResolvedServer>| async move { Ok(server.name.clone()) };
        for expected in [DEFAULT_SERVER_NAME, "backup", DEFAULT_SERVER_NAME] {
            assert_eq!(pool.connect_exit(DEFAULT_SERVER_NAME, success).await.unwrap(), expected);
        }
        pool.strategy = ExitStrategy::Failover;
        let only_backup = |server: Arc<ResolvedServer>| async move {
            anyhow::ensure!(server.name == "backup", "unreachable");
            Ok(server.name.clone())
        };
        assert_eq!(pool.connect_exit(DEFAULT_SERVER_NAME, only_backup).await.unwrap(), "backup");
        assert!(pool.connect_exit("backup", |server| async move { anyhow::ensure!(server.name == DEFAULT_SERVER_NAME, "offline"); Ok(()) }).await.is_err());
        pool.strategy = ExitStrategy::Primary;
        assert!(pool.connect_exit(DEFAULT_SERVER_NAME, only_backup).await.is_err());
    }

    /// The resumption store rides on `ResolvedServer` (one per exit) and is
    /// Arc-shared through every clone, so all connect calls a pool entry or
    /// relay makes against that exit — first connect, failure replacement,
    /// rotation replacement — see the same TLS session state. Distinct exits
    /// must never share tickets.
    #[test]
    fn resumption_store_shared_across_clones_independent_per_exit() {
        use rustls::pki_types::ServerName;

        let server = test_server("default");
        let other = test_server("hk");

        // Each connect call clones the entry's store; a write through one
        // clone must be visible to the next connect's clone.
        let first = server.resumption.rustls_session_store();
        let second = server.resumption.rustls_session_store();
        let name: ServerName<'static> = ServerName::try_from("exit.example.com").unwrap();
        first.set_kx_hint(name.clone(), rustls::NamedGroup::X25519);
        assert_eq!(
            second.kx_hint(&name),
            Some(rustls::NamedGroup::X25519),
            "clones of one exit's store must share session state"
        );
        assert_eq!(
            other.resumption.rustls_session_store().kx_hint(&name),
            None,
            "distinct exits must not share session state"
        );
    }
}
