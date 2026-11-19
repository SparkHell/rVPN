//! Split tunneling for VPN traffic routing (Client-side)
//!
//! This module provides client-side functionality to route traffic either through 
//! the VPN tunnel or directly (bypass), based on IP ranges and domain lists.
//!
//! Priority order (highest to lowest):
//! 0. VPN transport endpoint exemptions - Always route directly
//! 1. tunnel_domains - Force through VPN
//! 2. bypass_domains - Route directly
//! 3. tunnel_networks - Force through VPN
//! 4. bypass_networks - Route directly
//!
//! If no match is found, traffic goes through the VPN tunnel by default.
//!
//! ## Data Sources
//!
//! Built-in IP ranges are sourced from APNIC (Asia Pacific Network Information Centre)
//! delegations data: https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
//!
//! Supported countries: CN, HK, SG, JP, KR, TW (and more via configuration)

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::SplitTunnelConfig;
use crate::dns_cache::DnsResolver;

// Built-in IP ranges (feature-gated, ~484KB binary size)
#[cfg(feature = "builtin-ips")]
use crate::builtin_ips::get_country_ips;
#[cfg(feature = "builtin-ips")]
#[allow(unused_imports)]
use crate::builtin_ips::supported_countries;

// Built-in domain lists (feature-gated)
#[cfg(feature = "builtin-domains")]
use crate::builtin_domains::matches_ad_domain;

// Stub implementations when features are disabled
#[cfg(not(feature = "builtin-ips"))]
fn get_country_ips(_country_code: &str) -> Option<&'static [&'static str]> {
    None
}

#[cfg(not(feature = "builtin-domains"))]
#[allow(dead_code)]
fn matches_ad_domain(_domain: &str) -> bool { false }

/// Routing decision for a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Route through VPN tunnel
    Tunnel,
    /// Bypass VPN, route directly
    Bypass,
    /// Block the connection (for ad blocking)
    Block,
}

/// Internal data structure for split tunnel rules
struct SplitTunnelData {
    /// Networks that should bypass VPN
    bypass_networks: IpNetworkTable<bool>,
    /// Domains that should bypass VPN
    bypass_domains: HashSet<String>,
    /// Networks that must go through VPN
    tunnel_networks: IpNetworkTable<bool>,
    /// Domains that must go through VPN
    tunnel_domains: HashSet<String>,
    gfwlist: crate::gfwlist::Rules,
    /// Domains to block (ads, tracking, malware)
    block_domains: HashSet<String>,
    /// Last reload time
    last_reload: Instant,
}

impl std::fmt::Debug for SplitTunnelData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplitTunnelData")
            .field("bypass_networks_count", &self.bypass_networks.iter().count())
            .field("bypass_domains_count", &self.bypass_domains.len())
            .field("tunnel_networks_count", &self.tunnel_networks.iter().count())
            .field("tunnel_domains_count", &self.tunnel_domains.len())
            .field("block_domains_count", &self.block_domains.len())
            .field("last_reload", &self.last_reload)
            .finish()
    }
}

impl Clone for SplitTunnelData {
    fn clone(&self) -> Self {
        // Create new empty tables and re-insert all networks
        let mut bypass_networks = IpNetworkTable::new();
        for (network, _) in self.bypass_networks.iter() {
            bypass_networks.insert(network, true);
        }
        
        let mut tunnel_networks = IpNetworkTable::new();
        for (network, _) in self.tunnel_networks.iter() {
            tunnel_networks.insert(network, true);
        }
        
        Self {
            bypass_networks,
            bypass_domains: self.bypass_domains.clone(),
            tunnel_networks,
            tunnel_domains: self.tunnel_domains.clone(),
            gfwlist: self.gfwlist.clone(),
            block_domains: self.block_domains.clone(),
            last_reload: self.last_reload,
        }
    }
}

impl Default for SplitTunnelData {
    fn default() -> Self {
        Self {
            bypass_networks: IpNetworkTable::new(),
            bypass_domains: HashSet::new(),
            tunnel_networks: IpNetworkTable::new(),
            tunnel_domains: HashSet::new(),
            gfwlist: crate::gfwlist::Rules::default(),
            block_domains: HashSet::new(),
            last_reload: Instant::now(),
        }
    }
}

/// Split tunnel manager with hot-reload support
#[derive(Debug)]
pub struct SplitTunnel {
    /// Configuration
    config: SplitTunnelConfig,
    /// Internal data (protected by RwLock for thread-safe hot-reload)
    data: Arc<RwLock<SplitTunnelData>>,
    /// DNS resolver with caching
    dns_resolver: Arc<DnsResolver>,
    /// Transport endpoints are always direct, independently of user rules.
    /// Keep these outside reloadable data so rule-file reloads cannot erase them.
    server_bypass: RwLock<ServerBypass>,
}

#[derive(Debug, Default)]
struct ServerBypass {
    hosts: HashSet<String>,
    ips: HashSet<IpAddr>,
    resolved: HashMap<String, HashSet<IpAddr>>,
}

impl ServerBypass {
    fn contains_ip(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip) || self.resolved.values().any(|ips| ips.contains(ip))
    }
}

const SERVER_BYPASS_REASON: &str = "VPN 服务端地址自动直连（防止循环代理）";

fn normalize_server_host(host: &str) -> String {
    host.trim().trim_end_matches('.').trim_matches(['[', ']']).to_ascii_lowercase()
}

impl SplitTunnel {
    /// Create a new split tunnel manager from configuration
    pub async fn new(config: SplitTunnelConfig, dns_resolver: Arc<DnsResolver>) -> Result<Self> {
        let data = if config.enabled {
            Self::load_data(&config).await?
        } else {
            SplitTunnelData::default()
        };

        let split_tunnel = Self {
            config,
            data: Arc::new(RwLock::new(data)),
            dns_resolver,
            server_bypass: RwLock::default(),
        };

        // Start auto-reload task if enabled
        if split_tunnel.config.enabled && split_tunnel.config.auto_reload_interval > 0 {
            let data_clone = Arc::clone(&split_tunnel.data);
            let config_clone = split_tunnel.config.clone();
            let interval = Duration::from_secs(split_tunnel.config.auto_reload_interval);

            tokio::spawn(async move {
                auto_reload_task(data_clone, config_clone, interval).await;
            });
        }

        Ok(split_tunnel)
    }

    /// Create a disabled split tunnel manager (no routing rules)
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            config: SplitTunnelConfig::default(),
            data: Arc::new(RwLock::new(SplitTunnelData::default())),
            dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
            server_bypass: RwLock::default(),
        }
    }

    /// Check if split tunneling is enabled
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Access the shared DNS resolver (for caching)
    #[allow(dead_code)]
    pub fn dns_resolver(&self) -> Arc<DnsResolver> {
        Arc::clone(&self.dns_resolver)
    }

    /// Exact endpoint hostnames, not suffix rules: unrelated subdomains must
    /// retain their configured routing. Literal IPv4/IPv6 endpoints also bypass.
    pub async fn set_server_endpoints(&self, hosts: &[String]) {
        let mut bypass = ServerBypass::default();
        for host in hosts {
            let host = normalize_server_host(host);
            if let Ok(ip) = host.parse() { bypass.ips.insert(ip); }
            bypass.hosts.insert(host);
        }
        *self.server_bypass.write().await = bypass;
    }

    /// Called before dialing the transport, including DNS refresh / ECH targets.
    pub async fn set_server_ips(&self, host: &str, ips: &[IpAddr]) {
        let host = normalize_server_host(host);
        let mut bypass = self.server_bypass.write().await;
        if bypass.hosts.contains(&host) {
            bypass.resolved.insert(host, ips.iter().copied().collect());
        }
    }

    async fn is_server_host(&self, host: &str) -> bool {
        let host = normalize_server_host(host);
        let bypass = self.server_bypass.read().await;
        bypass.hosts.contains(&host)
            || host.parse::<IpAddr>().is_ok_and(|ip| bypass.contains_ip(&ip))
    }

    async fn are_server_ips(&self, ips: &[IpAddr]) -> bool {
        if ips.is_empty() { return false; }
        let bypass = self.server_bypass.read().await;
        ips.iter().all(|ip| bypass.contains_ip(ip))
    }

    /// Apply domain rules first, then the destination IP rules.
    pub async fn decide(&self, host: &str, ips: &[IpAddr]) -> RoutingDecision {
        if self.are_server_ips(ips).await { return RoutingDecision::Bypass; }
        if let Some((route, _, _)) = self.match_domain_rule(host).await {
            return route;
        }
        self.explain_ips(ips).await.0
    }

    fn gfwlist_match(&self, host: &str, data: &SplitTunnelData) -> bool {
        self.config.gfwlist_enabled && self.config.subscriptions.as_ref()
            .and_then(|s| s.matches(crate::subscriptions::Source::GfwList, host))
            .unwrap_or_else(|| data.gfwlist.forces_proxy(host))
    }

    /// Make a routing decision for a host without resolved IPs
    /// This is useful when only the hostname is known
    pub async fn decide_by_host(&self, host: &str) -> RoutingDecision {
        self.decide_dns(host).await.0
    }

    /// Returns the route and whether the GFWList rule selected it.
    pub async fn decide_dns(&self, host: &str) -> (RoutingDecision, bool) {
        let (route, gfwlist, _) = self.explain_dns(host).await;
        (route, gfwlist)
    }

    pub async fn explain_dns(&self, host: &str) -> (RoutingDecision, bool, &'static str) {
        self.match_domain_rule(host).await
            .unwrap_or((RoutingDecision::Bypass, false, "未命中域名规则，DNS 默认使用本地上游"))
    }

    async fn match_domain_rule(&self, host: &str) -> Option<(RoutingDecision, bool, &'static str)> {
        if self.is_server_host(host).await {
            return Some((RoutingDecision::Bypass, false, SERVER_BYPASS_REASON));
        }
        let host = host.trim_end_matches('.');
        if !self.config.enabled {
            return Some((RoutingDecision::Tunnel, false, "分流已关闭"));
        }

        let data = self.data.read().await;

        // Check ad/tracker domains first (highest priority)
        if self.config.block_ads
            && (Self::matches_domain(host, &data.block_domains) || self.config.subscriptions.as_ref().and_then(|s| s.matches(crate::subscriptions::Source::AdGuard, host)).unwrap_or_else(|| matches_ad_domain(host)))
        {
            debug!("Host {} matches ad/tracker domain list - blocking", host);
            return Some((RoutingDecision::Block, false, "命中广告过滤"));
        }

        // Check tunnel domains first (highest priority)
        if Self::matches_domain(host, &data.tunnel_domains) {
            debug!("Host {} matches tunnel domain list", host);
            return Some((RoutingDecision::Tunnel, false, "命中隧道域名规则"));
        }

        // Check bypass domains from file
        if Self::matches_domain(host, &data.bypass_domains) {
            debug!("Host {} matches bypass domain list", host);
            return Some((RoutingDecision::Bypass, false, "命中直连域名规则"));
        }

        if self.gfwlist_match(host, &data) {
            debug!("Host {} matches gfwlist proxy domain", host);
            return Some((RoutingDecision::Tunnel, true, "命中 GFWList"));
        }

        None
    }

    /// Explicit tunnel decisions skip local DNS probing.
    pub async fn requires_tunnel(&self, host: &str) -> bool {
        self.match_domain_rule(host).await.is_some_and(|(decision, _, _)| decision == RoutingDecision::Tunnel)
    }

    /// For a connection, use address rules only when no domain rule matched.
    pub async fn decide_for_connection(&self, host: &str) -> RoutingDecision {
        self.explain_connection(host).await.0
    }

    pub async fn explain_connection(&self, host: &str) -> (RoutingDecision, &'static str, Vec<IpAddr>) {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            let (decision, reason) = self.explain_ips(&[ip]).await;
            return (decision, reason, vec![ip]);
        }
        if let Some((decision, _, reason)) = self.match_domain_rule(host).await {
            return (decision, reason, Vec::new());
        }
        let ips = self.resolve_host_to_ips(host).await.unwrap_or_default();
        let (decision, reason) = self.explain_ips(&ips).await;
        (decision, reason, ips)
    }

    /// Check if a domain matches any pattern in the set
    /// Supports parent domain matching (e.g., "google.com" matches "www.google.com")
    fn matches_domain(host: &str, domains: &HashSet<String>) -> bool {
        // Normalize host to lowercase for case-insensitive matching
        let host = host.to_lowercase();
        if domains.contains(&host) {
            return true;
        }

        // Check parent domains
        let parts: Vec<&str> = host.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if domains.contains(&parent) {
                return true;
            }
        }

        false
    }

    /// Resolve a hostname to IP addresses (uses cached DNS resolver)
    pub async fn resolve_host_to_ips(&self, host: &str) -> Option<Vec<IpAddr>> {
        let addrs: Vec<std::net::SocketAddr> = match self.dns_resolver.resolve(host, 0).await {
            Ok(addrs) => addrs,
            Err(e) => {
                debug!("Failed to resolve {}: {}", host, e);
                return None;
            }
        };
        let ips: Vec<_> = addrs.into_iter().map(|a| a.ip()).collect();
        if self.is_server_host(host).await { self.set_server_ips(host, &ips).await; }
        Some(ips)
    }

    pub async fn decide_by_ip(&self, ip: IpAddr) -> RoutingDecision {
        self.explain_ips(&[ip]).await.0
    }

    async fn explain_ips(&self, ips: &[IpAddr]) -> (RoutingDecision, &'static str) {
        if self.are_server_ips(ips).await { return (RoutingDecision::Bypass, SERVER_BYPASS_REASON); }
        if !self.config.enabled {
            return (RoutingDecision::Tunnel, "分流已关闭");
        }
        let data = self.data.read().await;
        if ips.iter().any(|ip| data.tunnel_networks.longest_match(*ip).is_some()) {
            return (RoutingDecision::Tunnel, "命中隧道 IP 网段");
        }
        if ips.is_empty() {
            return (RoutingDecision::Tunnel, "本地 DNS 未返回可用地址");
        }
        if ips.iter().all(|ip| data.bypass_networks.longest_match(*ip).is_some()) {
            return (RoutingDecision::Bypass, "目标地址均命中直连网段");
        }
        if self.config.builtin_bypass_countries.is_empty() {
            return (RoutingDecision::Bypass, "未配置直连地区，未命中隧道规则");
        }
        (RoutingDecision::Tunnel, "至少一个目标地址未命中直连网段")
    }

    /// Manually trigger a reload of the configuration files
    #[allow(dead_code)]
    pub async fn reload(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        info!("Reloading split tunnel configuration...");
        let new_data = Self::load_data(&self.config).await?;

        let mut data = self.data.write().await;
        *data = new_data;
        drop(data);

        info!("Split tunnel configuration reloaded successfully");
        Ok(())
    }

    /// Get statistics about the loaded rules
    #[allow(dead_code)]
    pub async fn get_stats(&self) -> SplitTunnelStats {
        let data = self.data.read().await;
        SplitTunnelStats {
            bypass_networks_count: data.bypass_networks.iter().count(),
            bypass_domains_count: data.bypass_domains.len(),
            tunnel_networks_count: data.tunnel_networks.iter().count(),
            tunnel_domains_count: data.tunnel_domains.len(),
            last_reload: data.last_reload,
        }
    }

    /// Load data from configuration files and built-in sources
    async fn load_data(config: &SplitTunnelConfig) -> Result<SplitTunnelData> {
        let mut data = SplitTunnelData {
            last_reload: Instant::now(),
            ..Default::default()
        };
        data.gfwlist = crate::gfwlist::builtin().clone();

        // Load built-in private networks (RFC 1918) as default bypass networks
        // These are always loaded for security and to enable local network access
        let default_bypass_networks = [
            // IPv4 private networks
            "192.168.0.0/16",    // Private network (home routers)
            "10.0.0.0/8",        // Private network (large networks)
            "172.16.0.0/12",     // Private network (medium networks)
            "127.0.0.0/8",       // Loopback
            "169.254.0.0/16",    // Link-local (APIPA)
            "224.0.0.0/4",       // Multicast
            "240.0.0.0/4",       // Reserved for future use
            "100.64.0.0/10",     // Carrier-grade NAT (Shared address space)
            "192.0.0.0/24",      // IETF Protocol Assignments
            "192.0.2.0/24",      // TEST-NET-1 (documentation)
            "198.51.100.0/24",   // TEST-NET-2 (documentation)
            "203.0.113.0/24",    // TEST-NET-3 (documentation)
            // IPv6 private networks
            "::1/128",           // IPv6 loopback
            "fc00::/7",          // IPv6 unique local addresses (ULA)
            "fe80::/10",         // IPv6 link-local
            "ff00::/8",          // IPv6 multicast
        ];

        let mut loaded = 0;
        let mut failed = 0;
        for cidr in default_bypass_networks {
            match cidr.parse::<IpNetwork>() {
                Ok(network) => {
                    data.bypass_networks.insert(network, true);
                    loaded += 1;
                }
                Err(e) => {
                    debug!("Failed to parse default bypass network {}: {}", cidr, e);
                    failed += 1;
                }
            }
        }
        info!("Loaded {} default bypass networks ({} failed)", loaded, failed);

        // Load inline bypass networks from config (overrides defaults)
        for cidr in &config.bypass_networks {
            match cidr.parse::<IpNetwork>() {
                Ok(network) => {
                    data.bypass_networks.insert(network, true);
                    debug!("Loaded inline bypass network: {}", cidr);
                }
                Err(e) => {
                    warn!("Failed to parse inline bypass network {}: {}", cidr, e);
                }
            }
        }

        // Load IP ranges for configured countries.
        // Priority: country_ips_file (dynamic) > builtin_ips (compiled-in)
        let mut use_builtin_country_ips = config.country_ips_file.is_none();
        if let Some(ref path) = config.country_ips_file {
            match Self::load_country_ips_file(path, &config.builtin_bypass_countries).await {
                Ok(by_country) => {
                    let mut count = 0;
                    for cidrs in by_country.into_values() {
                        count += cidrs.len();
                        for cidr in &cidrs {
                            data.bypass_networks.insert(cidr.clone(), true);
                        }
                    }
                    info!("Loaded {} bypass IPs from country_ips_file {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load country IPs from {:?}: {}", path, e);
                    use_builtin_country_ips = true;
                }
            }
        }
        if use_builtin_country_ips {
            // Fall back to compiled-in IPs if the external file is unavailable.
            for country_code in &config.builtin_bypass_countries {
                if let Some(ip_ranges) = get_country_ips(country_code) {
                    let mut loaded = 0;
                    let mut failed = 0;
                    for cidr in ip_ranges {
                        match cidr.parse::<IpNetwork>() {
                            Ok(network) => {
                                data.bypass_networks.insert(network.clone(), true);
                                loaded += 1;
                            }
                            Err(e) => {
                                debug!("Failed to parse built-in IP {} for {}: {}", cidr, country_code, e);
                                failed += 1;
                            }
                        }
                    }
                    info!("Loaded {} built-in {} IP ranges ({} failed)", loaded, country_code, failed);
                } else {
                    warn!("Unknown country code for built-in IPs: {}", country_code);
                }
            }
        }

        // Load bypass networks from file
        if let Some(ref path) = config.bypass_networks_file {
            match Self::load_networks(path).await {
                Ok(networks) => {
                    let count = networks.len();
                    for network in networks {
                        data.bypass_networks.insert(network, true);
                    }
                    info!("Loaded {} bypass networks from {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load bypass networks from {:?}: {}", path, e);
                }
            }
        }

        // Load bypass domains
        data.bypass_domains.extend(config.bypass_domains.iter().map(|v| v.trim().trim_end_matches('.').to_ascii_lowercase()));
        data.tunnel_domains.extend(config.tunnel_domains.iter().map(|v| v.trim().trim_end_matches('.').to_ascii_lowercase()));
        for cidr in &config.tunnel_networks {
            data.tunnel_networks.insert(cidr.trim().parse::<IpNetwork>()?, true);
        }

        // Load unconditional bypass domains
        if let Some(ref path) = config.bypass_domains_file {
            match Self::load_domains(path).await {
                Ok(domains) => {
                    let count = domains.len();
                    data.bypass_domains.extend(domains);
                    info!("Loaded {} bypass domains from {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load bypass domains from {:?}: {}", path, e);
                }
            }
        }

        // Load tunnel networks
        if let Some(ref path) = config.tunnel_networks_file {
            match Self::load_networks(path).await {
                Ok(networks) => {
                    let count = networks.len();
                    for network in networks {
                        data.tunnel_networks.insert(network, true);
                    }
                    info!("Loaded {} tunnel networks from {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load tunnel networks from {:?}: {}", path, e);
                }
            }
        }

        // Load tunnel domains
        if let Some(ref path) = config.tunnel_domains_file {
            match Self::load_domains(path).await {
                Ok(domains) => {
                    let count = domains.len();
                    data.tunnel_domains.extend(domains);
                    info!("Loaded {} tunnel domains from {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load tunnel domains from {:?}: {}", path, e);
                }
            }
        }

        // Load ad-block domains
        if let Some(path) = config.ad_block_file.as_ref().filter(|_| config.block_ads) {
            match Self::load_domains(path).await {
                Ok(domains) => {
                    let count = domains.len();
                    data.block_domains.extend(domains);
                    info!("Loaded {} ad-block domains from {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load ad-block domains from {:?}: {}", path, e);
                }
            }
        }

        // Log summary
        let bypass_nets: usize = data.bypass_networks.iter().count();
        let tunnel_nets: usize = data.tunnel_networks.iter().count();
        #[cfg(feature = "builtin-domains")]
        let builtin_domain_count = if config.builtin_bypass_countries.contains(&"CN".to_string()) {
            crate::builtin_domains::CHINA_DOMAINS.len()
        } else {
            0
        };
        #[cfg(not(feature = "builtin-domains"))]
        let builtin_domain_count = 0;
        info!(
            "Split tunnel rules loaded: {} bypass networks, {} bypass domains ({} built-in CN), {} tunnel networks, {} tunnel domains, {} block domains, {} gfwlist proxy domains ({} exceptions)",
            bypass_nets,
            data.bypass_domains.len(),
            builtin_domain_count,
            tunnel_nets,
            data.tunnel_domains.len(),
            data.block_domains.len(),
            data.gfwlist.proxy.len(),
            data.gfwlist.exceptions.len()
        );

        Ok(data)
    }

    /// Load country IPs from a JSON file.
    /// Format: {"CN": ["1.0.1.0/24", ...], "HK": [...]}
    /// Only loads CIDRs for the specified country codes.
    async fn load_country_ips_file(path: &Path, countries: &[String]) -> Result<HashMap<String, Vec<IpNetwork>>> {
        let content = tokio::fs::read_to_string(path).await?;
        let map: std::collections::HashMap<String, Vec<String>> = serde_json::from_str(&content)?;

        let mut by_country = HashMap::new();
        for country_code in countries {
            let cidrs = map.get(country_code).ok_or_else(|| {
                anyhow::anyhow!("country IP file has no entry for {}", country_code)
            })?;
            let mut networks = Vec::new();
            for cidr in cidrs {
                match cidr.parse::<IpNetwork>() {
                    Ok(n) => networks.push(n),
                    Err(e) => debug!("Invalid CIDR {} in {}: {}", cidr, country_code, e),
                }
            }
            if networks.is_empty() {
                anyhow::bail!("country IP file contains no valid CIDRs for {}", country_code);
            }
            by_country.insert(country_code.clone(), networks);
        }
        Ok(by_country)
    }

    /// Load networks from a file (one CIDR per line)
    async fn load_networks(path: &Path) -> Result<Vec<IpNetwork>> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut networks = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse CIDR
            match line.parse::<IpNetwork>() {
                Ok(network) => networks.push(network),
                Err(e) => {
                    warn!("Invalid CIDR '{}': {}", line, e);
                }
            }
        }

        Ok(networks)
    }

    /// Load domains from a file (one domain per line)
    async fn load_domains(path: &Path) -> Result<HashSet<String>> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut domains = HashSet::new();

        for line in content.lines() {
            let line = line.trim().to_lowercase();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Remove any trailing dots (FQDN format)
            let domain = line.trim_end_matches('.').to_string();

            if !domain.is_empty() {
                domains.insert(domain);
            }
        }

        Ok(domains)
    }

    /// Load from files directly (for initial loading without async runtime)
    #[allow(dead_code)]
    pub fn load_from_files_sync(config: &SplitTunnelConfig) -> Result<Self> {
        let rt = tokio::runtime::Handle::try_current();
        
        let data = match rt {
            Ok(handle) => {
                // We're in an async context, use block_in_place
                tokio::task::block_in_place(|| {
                    handle.block_on(async { Self::load_data(config).await })
                })?
            }
            Err(_) => {
                // No runtime, create a temporary one
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(async { Self::load_data(config).await })?
            }
        };

        Ok(Self {
            config: config.clone(),
            data: Arc::new(RwLock::new(data)),
            dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
            server_bypass: RwLock::default(),
        })
    }
}

/// Statistics about split tunnel configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SplitTunnelStats {
    pub bypass_networks_count: usize,
    pub bypass_domains_count: usize,
    #[allow(dead_code)]
    pub tunnel_networks_count: usize,
    #[allow(dead_code)]
    pub tunnel_domains_count: usize,
    #[allow(dead_code)]
    pub last_reload: Instant,
}

/// Background task for auto-reloading configuration
async fn auto_reload_task(
    data: Arc<RwLock<SplitTunnelData>>,
    config: SplitTunnelConfig,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // Initial rules were already loaded by new().

    loop {
        ticker.tick().await;

        debug!("Auto-reloading split tunnel configuration...");
        
        match SplitTunnel::load_data(&config).await {
            Ok(new_data) => {
                let mut data_guard = data.write().await;
                *data_guard = new_data;
                drop(data_guard);
                debug!("Split tunnel configuration auto-reloaded successfully");
            }
            Err(e) => {
                warn!("Failed to auto-reload split tunnel configuration: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn server_endpoints_bypass_even_when_split_tunneling_is_disabled() {
        let split = SplitTunnel::new(
            SplitTunnelConfig { enabled: false, ..Default::default() },
            Arc::new(DnsResolver::new(true, 300, 1000, true, false, vec![])),
        ).await.unwrap();
        split.set_server_endpoints(&["VPN.Example.".into(), "203.0.113.10".into(), "[2001:db8::10]".into()]).await;
        for host in ["vpn.example", "VPN.EXAMPLE.", "203.0.113.10", "[2001:db8::10]"] {
            assert_eq!(split.decide_by_host(host).await, RoutingDecision::Bypass);
            assert_eq!(split.decide_for_connection(host).await, RoutingDecision::Bypass);
            assert!(!split.requires_tunnel(host).await);
        }
        assert_eq!(split.decide_by_host("sub.vpn.example").await, RoutingDecision::Tunnel);
        assert_eq!(split.decide_by_ip("203.0.113.11".parse().unwrap()).await, RoutingDecision::Tunnel);
    }

    #[tokio::test]
    async fn server_endpoints_override_block_and_tunnel_rules_and_survive_rule_reload() {
        let split = SplitTunnel::new(
            SplitTunnelConfig { enabled: true, block_ads: true, auto_reload_interval: 0,
                tunnel_domains: vec!["example".into()], tunnel_networks: vec!["0.0.0.0/0".into(), "::/0".into()], ..Default::default() },
            Arc::new(DnsResolver::new(true, 300, 1000, true, false, vec![])),
        ).await.unwrap();
        split.set_server_endpoints(&["vpn.example".into()]).await;
        split.data.write().await.block_domains.insert("example".into());
        let ips = ["203.0.113.10".parse().unwrap(), "2001:db8::10".parse().unwrap()];
        split.set_server_ips("vpn.example", &ips).await;
        assert_eq!(split.explain_dns("vpn.example").await.2, SERVER_BYPASS_REASON);
        assert_eq!(split.decide_by_host("vpn.example").await, RoutingDecision::Bypass);
        assert_eq!(split.decide_by_host("other.example").await, RoutingDecision::Block);
        for ip in ips { assert_eq!(split.decide_by_ip(ip).await, RoutingDecision::Bypass); }
        assert_eq!(split.decide("other.example", &ips).await, RoutingDecision::Bypass);
        split.reload().await.unwrap();
        assert_eq!(split.decide_by_host("vpn.example").await, RoutingDecision::Bypass);
        assert_eq!(split.decide_by_ip(ips[0]).await, RoutingDecision::Bypass);
        assert_eq!(split.decide_by_host("other.example").await, RoutingDecision::Tunnel);
    }

    #[tokio::test]
    async fn server_dns_changes_and_endpoint_replacement_remove_obsolete_exemptions() {
        let split = SplitTunnel::new(
            SplitTunnelConfig { enabled: false, ..Default::default() },
            Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
        ).await.unwrap();
        split.set_server_endpoints(&["vpn.example".into()]).await;
        let old = "203.0.113.10".parse().unwrap();
        let new = "203.0.113.11".parse().unwrap();
        split.set_server_ips("vpn.example", &[old]).await;
        assert_eq!(split.decide_by_ip(old).await, RoutingDecision::Bypass);
        split.set_server_ips("vpn.example", &[new]).await;
        assert_eq!(split.decide_by_ip(old).await, RoutingDecision::Tunnel);
        assert_eq!(split.decide_by_ip(new).await, RoutingDecision::Bypass);
        assert_eq!(split.decide("other.example", &[new, old]).await, RoutingDecision::Tunnel);
        split.set_server_ips("unknown.example", &[old]).await;
        assert_eq!(split.decide_by_ip(old).await, RoutingDecision::Tunnel);
        split.set_server_endpoints(&["backup.example".into()]).await;
        assert_eq!(split.decide_by_host("vpn.example").await, RoutingDecision::Tunnel);
        assert_eq!(split.decide_by_ip(new).await, RoutingDecision::Tunnel);
    }
    #[cfg(feature = "builtin-domains")]
    #[tokio::test]
    async fn builtin_gfwlist_works_with_existing_config_and_no_external_files() {
        let config:SplitTunnelConfig=toml::from_str("enabled = true\nauto_reload_interval = 0\n").unwrap();
        let fields=serde_json::to_value(&config).unwrap();
        assert_eq!(fields["gfwlistEnabled"], true);
        let blackhole=tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver=Arc::new(DnsResolver::new(true,300,1000,false,true,vec![])
            .with_nameservers(&[blackhole.local_addr().unwrap().to_string()]).unwrap());
        let split=SplitTunnel::new(config,resolver).await.unwrap();
        // Pick a domain supplied exclusively by GFWList, not the older short
        // force-tunnel list, so this cannot pass just because Google is built in.
        let domain=crate::gfwlist::builtin().proxy.iter().find(|domain| {
            !matches_ad_domain(domain) && crate::gfwlist::builtin().forces_proxy(domain)
        }).unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_millis(100),split.decide_for_connection(domain)).await.unwrap(),RoutingDecision::Tunnel);
    }
    #[tokio::test]
    async fn gfwlist_overrides_cn_ips_without_local_dns_and_respects_user_rules() {
        let config = SplitTunnelConfig { enabled:true, auto_reload_interval:0, ..Default::default() };
        // A nonresponsive resolver would make an accidental DNS probe stall.
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = Arc::new(DnsResolver::new(true,300,1000,false,true,vec![])
            .with_nameservers(&[blackhole.local_addr().unwrap().to_string()]).unwrap());
        let split = SplitTunnel::new(config,resolver).await.unwrap();
        split.data.write().await.gfwlist = crate::gfwlist::Rules {
            proxy: HashSet::from(["proxy.example".into()]),
            exceptions: HashSet::from(["except.proxy.example".into()]), skipped:0,
        };
        let routed = tokio::time::timeout(Duration::from_millis(100),split.decide_for_connection("www.proxy.example")).await.unwrap();
        assert_eq!(routed,RoutingDecision::Tunnel);
        assert!(split.requires_tunnel("www.proxy.example").await);
        assert!(!split.requires_tunnel("except.proxy.example").await);
        assert_eq!(split.decide("www.proxy.example",&["127.0.0.1".parse().unwrap()]).await,RoutingDecision::Tunnel);
        split.data.write().await.bypass_domains.insert("proxy.example".into());
        assert_eq!(split.decide_by_host("www.proxy.example").await,RoutingDecision::Bypass);
        split.data.write().await.tunnel_domains.insert("proxy.example".into());
        assert_eq!(split.decide_by_host("www.proxy.example").await,RoutingDecision::Tunnel);
    }
    use std::net::Ipv4Addr;

    #[test]
    fn test_domain_matching() {
        let mut domains = HashSet::new();
        domains.insert("google.com".to_string());
        domains.insert("baidu.com".to_string());

        assert!(SplitTunnel::matches_domain("google.com", &domains));
        assert!(SplitTunnel::matches_domain("www.google.com", &domains));
        assert!(SplitTunnel::matches_domain("mail.google.com", &domains));
        assert!(SplitTunnel::matches_domain("sub.mail.google.com", &domains));
        assert!(SplitTunnel::matches_domain("baidu.com", &domains));
        assert!(!SplitTunnel::matches_domain("example.com", &domains));
        assert!(!SplitTunnel::matches_domain("oogle.com", &domains));
    }

    #[test]
    fn test_routing_decision_by_host() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        rt.block_on(async {
            let mut data = SplitTunnelData::default();
            data.tunnel_domains.insert("google.com".to_string());
            data.bypass_domains.insert("baidu.com".to_string());

            let split_tunnel = SplitTunnel {
                config: SplitTunnelConfig {
                    enabled: true,
                    ..Default::default()
                },
                data: Arc::new(RwLock::new(data)),
                dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
                server_bypass: RwLock::default(),
            };

            // Tunnel domains should return Tunnel
            assert_eq!(
                split_tunnel.decide_by_host("google.com").await,
                RoutingDecision::Tunnel
            );
            assert_eq!(
                split_tunnel.decide_by_host("www.google.com").await,
                RoutingDecision::Tunnel
            );

            // Bypass domains should return Bypass
            assert_eq!(
                split_tunnel.decide_by_host("baidu.com").await,
                RoutingDecision::Bypass
            );
            assert_eq!(
                split_tunnel.decide_by_host("api.baidu.com").await,
                RoutingDecision::Bypass
            );

            // Unknown domains should default to Bypass
            assert_eq!(
                split_tunnel.decide_by_host("example.com").await,
                RoutingDecision::Bypass
            );
        });
    }

    #[test]
    fn test_routing_decision_with_ips() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        rt.block_on(async {
            let mut data = SplitTunnelData::default();
            
            // Add bypass network: 1.0.1.0/24
            let bypass_net: IpNetwork = "1.0.1.0/24".parse().unwrap();
            data.bypass_networks.insert(bypass_net, true);
            
            // Add tunnel network: 8.8.8.0/24
            let tunnel_net: IpNetwork = "8.8.8.0/24".parse().unwrap();
            data.tunnel_networks.insert(tunnel_net, true);

            let split_tunnel = SplitTunnel {
                config: SplitTunnelConfig {
                    enabled: true,
                    ..Default::default()
                },
                data: Arc::new(RwLock::new(data)),
                dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
                server_bypass: RwLock::default(),
            };

            // Test bypass network
            let bypass_ip = IpAddr::V4(Ipv4Addr::new(1, 0, 1, 100));
            assert_eq!(
                split_tunnel.decide("example.com", &[bypass_ip]).await,
                RoutingDecision::Bypass,
                "IP {} should match bypass network 1.0.1.0/24", bypass_ip
            );

            // Test tunnel network
            let tunnel_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            assert_eq!(
                split_tunnel.decide("example.com", &[tunnel_ip]).await,
                RoutingDecision::Tunnel
            );

            // Test an IP outside configured direct ranges
            let unknown_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(
                split_tunnel.decide("example.com", &[unknown_ip]).await,
                RoutingDecision::Tunnel
            );
        });
    }

    #[test]
    fn test_domain_priority_over_network() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        rt.block_on(async {
            let mut data = SplitTunnelData::default();
            
            // Add a domain to tunnel list
            data.tunnel_domains.insert("google.com".to_string());
            
            // Add the same IP to bypass list
            let bypass_net: IpNetwork = "8.8.8.0/24".parse().unwrap();
            data.bypass_networks.insert(bypass_net, true);

            let split_tunnel = SplitTunnel {
                config: SplitTunnelConfig {
                    enabled: true,
                    ..Default::default()
                },
                data: Arc::new(RwLock::new(data)),
                dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
                server_bypass: RwLock::default(),
            };

            // Domain match should take priority over network
            let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            assert_eq!(
                split_tunnel.decide("google.com", &[ip]).await,
                RoutingDecision::Tunnel
            );
        });
    }

    #[test]
    fn test_decide_by_ip() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        rt.block_on(async {
            let mut data = SplitTunnelData::default();
            
            // Add bypass network: 192.168.0.0/16 (RFC 1918)
            let bypass_net: IpNetwork = "192.168.0.0/16".parse().unwrap();
            data.bypass_networks.insert(bypass_net, true);
            
            // Add IPv6 loopback
            let bypass_net_v6: IpNetwork = "::1/128".parse().unwrap();
            data.bypass_networks.insert(bypass_net_v6, true);
            
            // Add tunnel network: 8.8.8.0/24
            let tunnel_net: IpNetwork = "8.8.8.0/24".parse().unwrap();
            data.tunnel_networks.insert(tunnel_net, true);

            let split_tunnel = SplitTunnel {
                config: SplitTunnelConfig {
                    enabled: true,
                    ..Default::default()
                },
                data: Arc::new(RwLock::new(data)),
                dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
                server_bypass: RwLock::default(),
            };

            // Test bypass network (192.168.x.x)
            let bypass_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(
                split_tunnel.decide_by_ip(bypass_ip).await,
                RoutingDecision::Bypass,
                "IP {} should match bypass network 192.168.0.0/16", bypass_ip
            );

            // Test tunnel network (8.8.8.x)
            let tunnel_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            assert_eq!(
                split_tunnel.decide_by_ip(tunnel_ip).await,
                RoutingDecision::Tunnel,
                "IP {} should match tunnel network 8.8.8.0/24", tunnel_ip
            );

            // Test an IP outside configured direct ranges
            let unknown_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
            assert_eq!(
                split_tunnel.decide_by_ip(unknown_ip).await,
                RoutingDecision::Tunnel,
                "IP {} outside the direct ranges should use the tunnel", unknown_ip
            );

            // Test IPv6 localhost
            let localhost_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
            assert_eq!(
                split_tunnel.decide_by_ip(localhost_v6).await,
                RoutingDecision::Bypass,
                "IPv6 localhost should match bypass network ::1/128"
            );
        });
    }

    #[test]
    fn test_decide_by_ip_disabled() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        rt.block_on(async {
            let data = SplitTunnelData::default();

            let split_tunnel = SplitTunnel {
                config: SplitTunnelConfig {
                    enabled: false,
                    ..Default::default()
                },
                data: Arc::new(RwLock::new(data)),
                dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
                server_bypass: RwLock::default(),
            };

            // When disabled, all traffic should tunnel
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(
                split_tunnel.decide_by_ip(ip).await,
                RoutingDecision::Tunnel,
                "When disabled, IP should default to Bypass"
            );
        });
    }

    /// End-to-end proof for the client toml option: a `[split_tunnel]
    /// tunnel_domains_file` entry must load the listed domains and force
    /// them (and their subdomains) through the VPN, even though their
    /// resolved IPs would normally be subject to bypass rules.
    #[test]
    fn test_tunnel_domains_file_config_forces_tunnel() {
        // 1. The snake_case key from a client.toml must deserialize.
        let dir = std::env::temp_dir().join(format!("rvpn-st-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let domains_file = dir.join("tunnel-domains.txt");
        std::fs::write(&domains_file, "# forced through the VPN\ntimestamp.apple.com\n").unwrap();

        let toml_str = format!(
            "enabled = true\ntunnel_domains_file = {:?}\nauto_reload_interval = 0\n",
            domains_file.to_string_lossy()
        );
        let config: SplitTunnelConfig =
            toml::from_str(&toml_str).expect("snake_case split-tunnel keys must parse");
        assert_eq!(config.tunnel_domains_file.as_deref(), Some(domains_file.as_path()));

        // 2. SplitTunnel::new must load the file into tunnel_domains.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let split_tunnel = SplitTunnel::new(
                config,
                Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
            )
            .await
            .expect("SplitTunnel::new must succeed with a valid domains file");

            let stats = split_tunnel.get_stats().await;
            assert_eq!(stats.tunnel_domains_count, 1, "file must load exactly its one domain");

            // 3. The domain and any subdomain must be forced through the VPN.
            assert_eq!(
                split_tunnel.decide_by_host("timestamp.apple.com").await,
                RoutingDecision::Tunnel
            );
            assert_eq!(
                split_tunnel.decide_by_host("sub.timestamp.apple.com").await,
                RoutingDecision::Tunnel
            );
            // Unrelated hosts are unaffected.
            assert_eq!(
                split_tunnel.decide_by_host("example.org").await,
                RoutingDecision::Bypass,
                "unmatched hosts connect directly"
            );
        });

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing domains file must not silently produce an empty rule set
    /// without surfacing it: load_data logs a warning and continues, and the
    /// stats must show zero tunnel domains so operators can spot it.
    #[test]
    fn test_tunnel_domains_file_missing_is_visible_in_stats() {
        let config = SplitTunnelConfig {
            enabled: true,
            tunnel_domains_file: Some(std::path::PathBuf::from("/nonexistent/rvpn-domains.txt")),
            ..Default::default()
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let split_tunnel = SplitTunnel::new(
                config,
                Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
            )
            .await
            .expect("missing file must not fail startup (warn + continue)");

            let stats = split_tunnel.get_stats().await;
            assert_eq!(
                stats.tunnel_domains_count, 0,
                "missing file must leave tunnel_domains empty (visible in startup stats)"
            );
        });
    }

    #[cfg(feature = "builtin-ips")]
    #[test]
    fn invalid_country_ips_file_falls_back_to_compiled_ranges() {
        let path = std::env::temp_dir().join(format!(
            "rvpn-invalid-country-ips-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "not JSON").unwrap();
        let config = SplitTunnelConfig {
            enabled: true,
            auto_reload_interval: 0,
            builtin_bypass_countries: vec!["CN".to_string()],
            country_ips_file: Some(path.clone()),
            ..Default::default()
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let split_tunnel = SplitTunnel::new(
                config,
                Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
            )
            .await
            .unwrap();
            assert_eq!(
                split_tunnel.decide_by_ip("1.0.1.1".parse().unwrap()).await,
                RoutingDecision::Bypass
            );
        });
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn generated_rule_files_route_and_block_only_when_enabled() {
        let dir = std::env::temp_dir().join(format!(
            "rvpn-generated-rules-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ad-domains.txt"), "ads.example.org\n").unwrap();
        std::fs::write(
            dir.join("country-domains-cn.txt"),
            "shop.example.cn\noutside.example.cn\n",
        )
        .unwrap();
        std::fs::write(dir.join("country-ips.json"), r#"{"CN":["7.7.7.0/24"]}"#).unwrap();
        let mut config = SplitTunnelConfig {
            enabled: true,
            block_ads: true,
            auto_reload_interval: 0,
            ad_block_file: Some(dir.join("ad-domains.txt")),
            country_domains_file: Some(dir.join("country-domains-cn.txt")),
            country_ips_file: Some(dir.join("country-ips.json")),
            builtin_bypass_countries: vec!["CN".to_string()],
            ..Default::default()
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let resolver = Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![]));
            resolver
                .store_with_ttl("shop.example.cn", vec!["7.7.7.7".parse().unwrap()], Duration::from_secs(300))
                .await;
            resolver
                .store_with_ttl("outside.example.cn", vec!["8.8.8.8".parse().unwrap()], Duration::from_secs(300))
                .await;
            let enabled = SplitTunnel::new(config.clone(), Arc::clone(&resolver)).await.unwrap();
            assert_eq!(enabled.decide_by_host("sub.ads.example.org").await, RoutingDecision::Block);
            assert_eq!(enabled.decide_by_host("shop.example.cn").await, RoutingDecision::Bypass);
            assert_eq!(enabled.decide_by_host("outside.example.cn").await, RoutingDecision::Bypass);
            assert_eq!(enabled.decide_for_connection("shop.example.cn").await, RoutingDecision::Bypass);
            assert_eq!(enabled.decide_for_connection("outside.example.cn").await, RoutingDecision::Tunnel);
            assert_eq!(enabled.decide_by_ip("7.7.7.7".parse().unwrap()).await, RoutingDecision::Bypass);

            config.block_ads = false;
            let disabled = SplitTunnel::new(config, resolver).await.unwrap();
            assert_eq!(disabled.decide_by_host("ads.example.org").await, RoutingDecision::Bypass);
        });
        std::fs::remove_dir_all(dir).unwrap();
    }
}
