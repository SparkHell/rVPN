//! Persist validated domain subscriptions and swap the live snapshot after a successful write.
use crate::gfwlist::Rules;
use anyhow::{ensure, Context, Result};
use base64::Engine;
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
            Self::AdGuard => &[
                "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
                "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
            ],
            Self::GfwList => {
                &["https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"]
            }
        }
    }
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
        let domain = match source {
            Source::AdGuard => rule
                .strip_prefix("||")
                .and_then(|v| v.strip_suffix('^'))
                .or_else(|| {
                    let mut fields = rule.split_whitespace();
                    let address = fields.next()?;
                    matches!(address, "127.0.0.1" | "0.0.0.0" | "::1")
                        .then(|| fields.next())
                        .flatten()
                }),
            Source::GfwList => Some(
                rule.trim_start_matches("||")
                    .trim_start_matches('.')
                    .trim_end_matches('^'),
            ),
        };
        let Some(domain) = domain.filter(|d| {
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
        }) else {
            rules.skipped += 1;
            continue;
        };
        let set = if exception {
            &mut rules.exceptions
        } else {
            &mut rules.proxy
        };
        set.insert(domain.to_ascii_lowercase());
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
                    Ok(rules) if !rules.proxy.is_empty() => Some(rules),
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
            .timeout(Duration::from_secs(22))
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
                rules.proxy.len() >= 1000,
                "有效域名不足 1000 条，保留上次规则：{url}"
            );
            combined.proxy.extend(rules.proxy);
            combined.exceptions.extend(rules.exceptions);
            combined.skipped += rules.skipped;
        }
        self.install(source, combined)
    }

    fn install(&self, source: Source, rules: Rules) -> Result<usize> {
        let count = rules.proxy.len();
        ensure!(count >= 1000, "有效域名不足 1000 条，保留上次规则");
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
}
