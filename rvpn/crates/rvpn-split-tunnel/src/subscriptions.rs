//! Persist validated domain subscriptions and swap the live snapshot after a successful write.
use crate::gfwlist::{PatternRule, Rules};
use anyhow::{ensure, Context, Result};
use base64::Engine;
use regex::RegexBuilder;
use std::{
    path::{Path, PathBuf},
    sync::RwLock,
    time::Duration,
};

#[derive(Debug, Clone, Copy)]
pub enum Source {
    AdGuard,
    GfwList,
}

impl Source {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "adguard" => Ok(Self::AdGuard),
            "gfwlist" => Ok(Self::GfwList),
            _ => anyhow::bail!("Unknown rule subscription"),
        }
    }
    fn filename(self) -> &'static str {
        match self {
            Self::AdGuard => "adguard.json",
            Self::GfwList => "gfwlist.json",
        }
    }
    fn urls(self) -> &'static [&'static str] {
        match self {
            Self::AdGuard => &["https://anti-ad.net/easylist.txt"],
            Self::GfwList => {
                &["https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"]
            }
        }
    }
}

fn is_valid_domain(d: &str) -> bool {
    d.len() <= 253
        && d.contains('.')
        && d.parse::<std::net::IpAddr>().is_err()
        && d.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

fn is_valid_wildcard_domain(d: &str) -> bool {
    d.len() <= 253
        && d.contains('.')
        && d.contains('*')
        && !d.starts_with('.')
        && !d.ends_with('.')
        && !d.contains("..")
        && d.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'*'))
}

fn wildcard_domain_to_regex(pattern: &str) -> String {
    let mut out = String::from("^(?:.*\\.)?");
    for ch in pattern.to_ascii_lowercase().chars() {
        match ch {
            '*' => out.push_str(".*"),
            '.' => out.push_str("\\."),
            _ => out.push(ch),
        }
    }
    out.push('$');
    out
}

fn regex_is_valid(pattern: &str) -> bool {
    !pattern.is_empty()
        && RegexBuilder::new(pattern)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .build()
            .is_ok()
}

/// Parse supported AdGuard Home DNS rule modifiers (`important`, `denyallow=...`, `dnstype=...`).
/// Returns `None` if an unsupported modifier is present so browser/URL/rewrite rules are skipped.
fn parse_adguard_modifiers(raw: &str) -> Option<Vec<String>> {
    let mut denyallow = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        if part.eq_ignore_ascii_case("important") {
            continue;
        }
        if let Some(list) = part.strip_prefix("denyallow=") {
            if list.is_empty() {
                return None;
            }
            for item in list.split('|') {
                let domain = item.trim().trim_end_matches('.');
                if !is_valid_domain(domain) {
                    return None;
                }
                denyallow.push(domain.to_ascii_lowercase());
            }
            continue;
        }
        if let Some(types) = part.strip_prefix("dnstype=") {
            let mut has_address_type = false;
            for item in types.split('|') {
                let item = item.trim();
                if item.is_empty() || item.starts_with('~') {
                    return None;
                }
                if item.eq_ignore_ascii_case("A")
                    || item.eq_ignore_ascii_case("AAAA")
                    || item.eq_ignore_ascii_case("CNAME")
                {
                    has_address_type = true;
                }
            }
            if !has_address_type {
                return None;
            }
            continue;
        }
        return None;
    }
    Some(denyallow)
}

fn parse_adguard_rule(rule: &str, exception: bool, rules: &mut Rules) -> bool {
    if rule.starts_with('/') {
        let Some(end) = rule.rfind('/') else {
            return false;
        };
        if end == 0 {
            return false;
        }
        let pattern = &rule[1..end];
        let rest = &rule[end + 1..];
        let denyallow = if rest.is_empty() {
            Vec::new()
        } else if let Some(mods) = rest.strip_prefix('$') {
            let Some(denyallow) = parse_adguard_modifiers(mods) else {
                return false;
            };
            denyallow
        } else {
            return false;
        };
        if !regex_is_valid(pattern) {
            return false;
        }
        if exception {
            if !denyallow.is_empty() {
                return false;
            }
            rules.exception_patterns.push(pattern.to_owned());
        } else {
            rules.patterns.push(PatternRule {
                pattern: pattern.to_owned(),
                denyallow,
            });
        }
        return true;
    }

    if rule.starts_with("||") {
        let (body, mods) = rule
            .split_once('$')
            .map_or((rule, None), |(b, m)| (b, Some(m)));
        let Some(domain) = body.strip_prefix("||").and_then(|v| v.strip_suffix('^')) else {
            return false;
        };
        let denyallow = match mods {
            Some(m) => {
                let Some(list) = parse_adguard_modifiers(m) else {
                    return false;
                };
                list
            }
            None => Vec::new(),
        };
        if is_valid_domain(domain) {
            if exception {
                if !denyallow.is_empty() {
                    return false;
                }
                rules.exceptions.insert(domain.to_ascii_lowercase());
            } else if denyallow.is_empty() {
                rules.proxy.insert(domain.to_ascii_lowercase());
            } else {
                let pattern = wildcard_domain_to_regex(domain);
                rules.patterns.push(PatternRule { pattern, denyallow });
            }
            return true;
        }
        if is_valid_wildcard_domain(domain) {
            let pattern = wildcard_domain_to_regex(domain);
            if !regex_is_valid(&pattern) {
                return false;
            }
            if exception {
                if !denyallow.is_empty() {
                    return false;
                }
                rules.exception_patterns.push(pattern);
            } else {
                rules.patterns.push(PatternRule { pattern, denyallow });
            }
            return true;
        }
        return false;
    }

    let mut fields = rule.split_whitespace();
    let Some(address) = fields.next() else {
        return false;
    };
    if !matches!(address, "127.0.0.1" | "0.0.0.0" | "::1") {
        return false;
    }
    let Some(domain) = fields.next().filter(|d| is_valid_domain(d)) else {
        return false;
    };
    if exception {
        rules.exceptions.insert(domain.to_ascii_lowercase());
    } else {
        rules.proxy.insert(domain.to_ascii_lowercase());
    }
    true
}

fn domains(source: Source, bytes: &[u8]) -> Result<Rules> {
    let text = std::str::from_utf8(bytes)?
        .trim_start_matches('\u{feff}')
        .trim();
    let decoded;
    let text = if matches!(source, Source::GfwList)
        && !text.contains('.')
        && !text.starts_with("[AutoProxy")
    {
        let compact: Vec<_> = text
            .bytes()
            .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
            .collect();
        decoded = base64::engine::general_purpose::STANDARD_NO_PAD.decode(compact)?;
        std::str::from_utf8(&decoded)?
    } else {
        text
    };
    let mut rules = Rules::default();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(['!', '#', '[']) {
            continue;
        }
        let (exception, rule) = line.strip_prefix("@@").map_or((false, line), |v| (true, v));
        match source {
            Source::AdGuard => {
                if !parse_adguard_rule(rule, exception, &mut rules) {
                    rules.skipped += 1;
                }
            }
            Source::GfwList => {
                let domain = rule
                    .trim_start_matches("||")
                    .trim_start_matches('.')
                    .trim_end_matches('^');
                if !is_valid_domain(domain) {
                    rules.skipped += 1;
                    continue;
                }
                let set = if exception {
                    &mut rules.exceptions
                } else {
                    &mut rules.proxy
                };
                set.insert(domain.to_ascii_lowercase());
            }
        }
    }
    Ok(rules)
}

#[derive(Debug)]
pub struct Subscriptions {
    directory: PathBuf,
    adguard: RwLock<Option<Rules>>,
    gfwlist: RwLock<Option<Rules>>,
    updating: tokio::sync::Mutex<()>,
}

impl Subscriptions {
    pub fn open(data_dir: &Path) -> Self {
        let directory = data_dir.join("subscriptions");
        let load = |source: Source| {
            let path = directory.join(source.filename());
            match std::fs::read(&path) {
                Ok(bytes) => match serde_json::from_slice::<Rules>(&bytes) {
                    Ok(rules) if !rules.proxy.is_empty() || !rules.patterns.is_empty() => {
                        rules.compile();
                        Some(rules)
                    }
                    _ => {
                        tracing::warn!("Invalid rule cache: {}", path.display());
                        None
                    }
                },
                Err(_) => None,
            }
        };
        Self {
            adguard: RwLock::new(load(Source::AdGuard)),
            gfwlist: RwLock::new(load(Source::GfwList)),
            directory,
            updating: Default::default(),
        }
    }
    fn slot(&self, source: Source) -> &RwLock<Option<Rules>> {
        match source {
            Source::AdGuard => &self.adguard,
            Source::GfwList => &self.gfwlist,
        }
    }
    pub fn matches(&self, source: Source, host: &str) -> Option<bool> {
        self.slot(source)
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|r| r.forces_proxy(host))
    }
    pub async fn update(&self, source: Source, proxy_url: &str) -> Result<usize> {
        let _guard = self.updating.try_lock().context("已有规则正在更新")?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .proxy(reqwest::Proxy::all(proxy_url).context("无效的规则更新代理")?)
            .timeout(Duration::from_secs(60))
            .build()?;
        let mut combined = Rules::default();
        for url in source.urls() {
            let mut response = client
                .get(*url)
                .send()
                .await
                .map_err(|error| error.without_url())
                .with_context(|| format!("无法通过代理下载 {url}"))?
                .error_for_status()?;
            ensure!(
                response.status() == reqwest::StatusCode::OK
                    && !response
                        .headers()
                        .contains_key(reqwest::header::CONTENT_RANGE),
                "规则源返回了不完整的文件：{url}"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    bytes.len() + chunk.len() <= 20 * 1024 * 1024,
                    "规则文件超过 20 MiB"
                );
                bytes.extend_from_slice(&chunk);
            }
            let rules = domains(source, &bytes)?;
            ensure!(
                rules.proxy.len() + rules.patterns.len() >= 1000,
                "有效域名不足 1000 条，保留上次规则：{url}"
            );
            combined.proxy.extend(rules.proxy);
            combined.exceptions.extend(rules.exceptions);
            combined.patterns.extend(rules.patterns);
            combined.exception_patterns.extend(rules.exception_patterns);
            combined.skipped += rules.skipped;
        }
        self.install(source, combined)
    }

    fn install(&self, source: Source, rules: Rules) -> Result<usize> {
        let count = rules.proxy.len() + rules.patterns.len();
        ensure!(count >= 1000, "有效域名不足 1000 条，保留上次规则");
        rules.compile();
        std::fs::create_dir_all(&self.directory)?;
        let mut file = tempfile::NamedTempFile::new_in(&self.directory)?;
        serde_json::to_writer(file.as_file_mut(), &rules)?;
        file.as_file().sync_all()?;
        file.persist(self.directory.join(source.filename()))?;
        *self.slot(source).write().unwrap_or_else(|e| e.into_inner()) = Some(rules);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downloaded_lists_preserve_exceptions_and_skip_url_rules() {
        for source in [Source::AdGuard, Source::GfwList] {
            let input = "||ads.example^\n@@||ok.ads.example^\n||bad.example/path";
            let bytes = match source {
                Source::AdGuard => input.to_owned(),
                Source::GfwList => base64::engine::general_purpose::STANDARD.encode(input),
            };
            let rules = domains(source, bytes.as_bytes()).unwrap();
            assert!(rules.forces_proxy("sub.ads.example"));
            assert!(!rules.forces_proxy("ok.ads.example"));
            assert!(!rules.forces_proxy("bad.example"));
            if matches!(source, Source::AdGuard) {
                let hosts = domains(source, b"127.0.0.1 tracker.example # comment").unwrap();
                assert!(hosts.forces_proxy("sub.tracker.example"));
            }
        }
    }
    #[test]
    fn a_new_store_reads_the_previous_subscription() {
        let dir = tempfile::tempdir().unwrap();
        let source = Source::AdGuard;
        let store = Subscriptions::open(dir.path());
        let valid = (0..1000)
            .map(|i| format!("||ad{i}.example^"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            store
                .install(source, domains(source, valid.as_bytes()).unwrap())
                .unwrap(),
            1000
        );
        assert!(store
            .install(source, domains(source, b"error page").unwrap())
            .is_err());
        assert_eq!(store.matches(source, "ad1.example"), Some(true));
        let store = Subscriptions::open(dir.path());
        assert_eq!(store.matches(source, "ad1.example"), Some(true));
        assert_eq!(store.matches(Source::GfwList, "restored.example"), None);
    }

    #[test]
    fn adguard_supports_wildcards_regex_and_modifiers() {
        let input = "\
! anti-AD samples
||ads*-normal-hl.zijieapi.com^
||*serror*.wo.com.cn^$dnstype=A|CNAME
@@||profile*.se.360.cn^
/^(\\S+\\.)?tongji\\./
/^(\\S+\\.)?advert/$denyallow=taobao.com|tmall.com
/^(\\S+\\.)?9377[a-z0-9]{2}\\.com$/$dnstype=A
||profile1.se.360.cn^
||httpsonly.example^$dnstype=HTTPS
||rewrite.example^$dnsrewrite=1.2.3.4
||bad.example/path*
";
        let rules = domains(Source::AdGuard, input.as_bytes()).unwrap();
        // Wildcard block & subdomain
        assert!(rules.forces_proxy("ads1-normal-hl.zijieapi.com"));
        assert!(rules.forces_proxy("sub.ads99-normal-hl.zijieapi.com"));
        assert!(!rules.forces_proxy("notads-normal-hl.zijieapi.com"));
        assert!(rules.forces_proxy("xserror1.wo.com.cn"));
        // Wildcard exception overrides plain block
        assert!(!rules.forces_proxy("profile1.se.360.cn"));
        assert!(!rules.forces_proxy("sub.profile2.se.360.cn"));
        // Regex rules
        assert!(rules.forces_proxy("tongji.example.com"));
        assert!(rules.forces_proxy("a.tongji.example.com"));
        assert!(rules.forces_proxy("9377ab.com"));
        assert!(rules.forces_proxy("sub.9377ab.com"));
        assert!(!rules.forces_proxy("9377abc.com"));
        // Regex with $denyallow
        assert!(rules.forces_proxy("advert.example.com"));
        assert!(!rules.forces_proxy("advert.taobao.com"));
        assert!(!rules.forces_proxy("sub.advert.tmall.com"));
        // Unsupported modifiers & URL rules are skipped
        assert!(!rules.forces_proxy("httpsonly.example"));
        assert!(!rules.forces_proxy("rewrite.example"));
        assert!(!rules.forces_proxy("bad.example"));
        assert_eq!(rules.skipped, 3);

        // Round-trip through JSON serialization
        let json = serde_json::to_vec(&rules).unwrap();
        let reloaded: Rules = serde_json::from_slice(&json).unwrap();
        assert!(reloaded.forces_proxy("ads1-normal-hl.zijieapi.com"));
        assert!(!reloaded.forces_proxy("advert.taobao.com"));
        assert!(!reloaded.forces_proxy("profile1.se.360.cn"));
    }
}
