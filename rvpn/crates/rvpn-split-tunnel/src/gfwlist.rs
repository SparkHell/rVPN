//! Build-time imported GFWList domain rules and AdGuard/anti-AD subscription
//! domain, wildcard, and regex rules.
use regex::{RegexBuilder, RegexSet, RegexSetBuilder};
use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PatternRule {
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denyallow: Vec<String>,
}

#[derive(Debug, Default)]
struct CompiledPatterns {
    proxy_set: Option<RegexSet>,
    proxy_denyallow: Vec<Vec<String>>,
    exception_set: Option<RegexSet>,
}

impl CompiledPatterns {
    fn compile(patterns: &[PatternRule], exception_patterns: &[String]) -> Self {
        let mut valid_proxy = Vec::with_capacity(patterns.len());
        let mut proxy_denyallow = Vec::with_capacity(patterns.len());
        for rule in patterns {
            if RegexBuilder::new(&rule.pattern)
                .case_insensitive(true)
                .size_limit(1 << 20)
                .build()
                .is_ok()
            {
                valid_proxy.push(rule.pattern.as_str());
                proxy_denyallow.push(rule.denyallow.clone());
            }
        }
        let proxy_set = (!valid_proxy.is_empty()).then(|| {
            RegexSetBuilder::new(&valid_proxy)
                .case_insensitive(true)
                .size_limit(10 * 1024 * 1024)
                .build()
                .ok()
        })
        .flatten();

        let valid_exc: Vec<&str> = exception_patterns
            .iter()
            .filter(|p| {
                RegexBuilder::new(p)
                    .case_insensitive(true)
                    .size_limit(1 << 20)
                    .build()
                    .is_ok()
            })
            .map(String::as_str)
            .collect();
        let exception_set = (!valid_exc.is_empty()).then(|| {
            RegexSetBuilder::new(&valid_exc)
                .case_insensitive(true)
                .size_limit(10 * 1024 * 1024)
                .build()
                .ok()
        })
        .flatten();

        Self {
            proxy_set,
            proxy_denyallow,
            exception_set,
        }
    }
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct Rules {
    pub proxy: HashSet<String>,
    pub exceptions: HashSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<PatternRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exception_patterns: Vec<String>,
    pub skipped: usize,
    #[serde(skip)]
    compiled: OnceLock<CompiledPatterns>,
}

impl Clone for Rules {
    fn clone(&self) -> Self {
        Self {
            proxy: self.proxy.clone(),
            exceptions: self.exceptions.clone(),
            patterns: self.patterns.clone(),
            exception_patterns: self.exception_patterns.clone(),
            skipped: self.skipped,
            compiled: OnceLock::new(),
        }
    }
}

fn matches(host: &str, rules: &HashSet<String>) -> bool {
    rules.contains(host)
        || host
            .match_indices('.')
            .any(|(i, _)| rules.contains(&host[i + 1..]))
}

fn matches_domain_slice(host: &str, domains: &[String]) -> bool {
    domains.iter().any(|domain| {
        host == domain
            || (host.len() > domain.len()
                && host.ends_with(domain.as_str())
                && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
    })
}

impl Rules {
    pub fn compile(&self) {
        if !self.patterns.is_empty() || !self.exception_patterns.is_empty() {
            let _ = self
                .compiled
                .get_or_init(|| CompiledPatterns::compile(&self.patterns, &self.exception_patterns));
        }
    }

    fn compiled(&self) -> Option<&CompiledPatterns> {
        if self.patterns.is_empty() && self.exception_patterns.is_empty() {
            return None;
        }
        Some(
            self.compiled
                .get_or_init(|| CompiledPatterns::compile(&self.patterns, &self.exception_patterns)),
        )
    }

    pub fn forces_proxy(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let matched = matches(&host, &self.proxy)
            || self
                .compiled()
                .and_then(|c| c.proxy_set.as_ref().map(|set| (c, set)))
                .is_some_and(|(c, set)| {
                    set.matches(&host)
                        .into_iter()
                        .any(|idx| !matches_domain_slice(&host, &c.proxy_denyallow[idx]))
                });
        if !matched {
            return false;
        }
        if matches(&host, &self.exceptions) {
            return false;
        }
        !self
            .compiled()
            .and_then(|c| c.exception_set.as_ref())
            .is_some_and(|set| set.is_match(&host))
    }
}

pub fn builtin() -> &'static Rules {
    static RULES: std::sync::OnceLock<Rules> = std::sync::OnceLock::new();
    RULES.get_or_init(|| {
        #[cfg(feature = "builtin-domains")]
        {
            serde_json::from_slice(include_bytes!("../data/gfwlist-rules.json"))
                .expect("validated build-time GFWList snapshot")
        }
        #[cfg(not(feature = "builtin-domains"))]
        {
            Rules::default()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_boundaries_and_exceptions_are_preserved() {
        let rules = Rules {
            proxy: HashSet::from(["example.com".into()]),
            exceptions: HashSet::from(["safe.example.com".into()]),
            ..Default::default()
        };
        assert!(rules.forces_proxy("WWW.EXAMPLE.COM."));
        assert!(!rules.forces_proxy("child.safe.example.com"));
        assert!(!rules.forces_proxy("notexample.com"));
    }

    #[cfg(feature = "builtin-domains")]
    #[test]
    fn snapshot_is_embedded_and_ready_without_downloads_or_configuration() {
        let rules = builtin();
        assert!(rules.proxy.len() > 1000);
        assert!(rules.forces_proxy("www.youtube.com"));
        assert!(rules.forces_proxy("www.google.com"));
        let source: serde_json::Value =
            serde_json::from_slice(include_bytes!("../data/gfwlist-source.json")).unwrap();
        assert_eq!(source["counts"]["proxy"], rules.proxy.len());
        assert_eq!(source["counts"]["exceptions"], rules.exceptions.len());
        assert_eq!(source["counts"]["skipped"], rules.skipped);
    }
}
