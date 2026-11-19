//! Re-export from rvpn-split-tunnel for backwards compatibility.
#![allow(unused_imports)]
pub use rvpn_split_tunnel::{
    SplitTunnel, RoutingDecision, SplitTunnelConfig,
    get_country_ips, get_country_domains,
    matches_china_domain, matches_ad_domain,
    is_china_domain, is_ad_domain,
    matches_force_tunnel_domain,
};

#[cfg(not(target_os = "android"))]
pub(crate) fn server_endpoint_hosts(config: &crate::config::ClientConfig) -> Vec<String> {
    std::iter::once(config.server_address.as_str())
        .chain(config.extra_servers.iter().map(|server| server.address.as_str()))
        .map(|address| crate::server_pool::parse_server_url(address).0)
        .collect()
}

/// Set transport exemptions before accepting proxy requests. DNS failures do
/// not prevent startup: exact hostnames still bypass and dial-time DNS results
/// are added again before the transport opens its socket.
#[cfg(not(target_os = "android"))]
pub(crate) async fn configure_server_bypass(split: &SplitTunnel, hosts: &[String]) {
    split.set_server_endpoints(hosts).await;
    futures::future::join_all(hosts.iter().map(|host| async move {
        if host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() { return; }
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), split.resolve_host_to_ips(host)).await;
        if !matches!(result, Ok(Some(ref ips)) if !ips.is_empty()) {
            tracing::warn!("VPN 服务端 {host} 的初始地址解析失败，域名仍保持直连，连接时将重试解析");
        }
    })).await;
}

#[cfg(all(test, not(target_os = "android")))]
mod endpoint_tests {
    #[test]
    fn collects_default_and_extra_endpoint_hosts_without_paths_or_ports() {
        let config: crate::config::ClientConfig = toml::from_str(r#"
server_address = "wss://vpn.example:8443/secret/path"
[[server]]
name = "backup"
address = "wss://[2001:db8::1]:443/ws"
prekey_bundle = "backup.json"
"#).unwrap();
        assert_eq!(super::server_endpoint_hosts(&config), vec!["vpn.example", "2001:db8::1"]);
    }
}
