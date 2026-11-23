//! Import the versioned public deployment link into a configuration draft.
use std::{io::Write, path::Path};

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use rvpn_core::{crypto::X3DHPublicBundle, identity_pin};
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerLink {
    v: u8,
    address: String,
    bundle: X3DHPublicBundle,
}

pub fn prepare(path: &Path, draft: &Value, link: &str, replace: bool) -> Result<Value> {
    let (scheme, encoded) = link.trim().split_once("://").context("需要 rVPN:// 链接")?;
    ensure!(
        scheme.eq_ignore_ascii_case("rvpn") && encoded.len() <= 8192,
        "无效的 rVPN 链接"
    );
    let data: ServerLink = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded)?)?;
    ensure!(data.v == 1, "不支持的链接版本");
    let url = Url::parse(&data.address)?;
    ensure!(
        url.scheme() == "wss"
            && url.host().is_some()
            && url.port() != Some(0)
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.query().is_none()
            && url.path() != "/",
        "需要带路径的 WSS 地址"
    );
    let bundle = data.bundle;
    let key = VerifyingKey::from_bytes(&bundle.identity_key)?;
    key.verify_strict(
        &bundle.signed_prekey,
        &Signature::from_bytes(&bundle.prekey_signature),
    )?;
    let fingerprint = crate::identity_verification::compute_fingerprint(&bundle);
    let base = path.parent().context("缺少配置目录")?;
    let mut nodes = draft["server"].as_array().cloned().unwrap_or_default();
    let same_address =
        |value: &Value| value.as_str().and_then(|s| Url::parse(s).ok()).as_ref() == Some(&url);
    let extra = nodes.iter().position(|node| same_address(&node["address"]));
    let same_primary = same_address(&draft["server_address"]);
    let primary_bundle = draft["prekey_bundle"].as_str().filter(|s| !s.is_empty());
    let primary = replace
        || same_primary
        || (extra.is_none() && primary_bundle.is_none_or(|s| !base.join(s).is_file()));
    let existing = if same_primary {
        primary_bundle
    } else {
        extra.and_then(|i| nodes[i]["prekey_bundle"].as_str())
    };
    let content = serde_json::to_vec_pretty(&bundle)?;
    if let Some(existing) = existing {
        let previous_path = base.join(existing);
        match previous_path.metadata() {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file() && metadata.len() <= 16384,
                    "预密钥包须为公开 JSON 文件"
                );
                let previous: X3DHPublicBundle =
                    serde_json::from_slice(&std::fs::read(previous_path)?)?;
                ensure!(
                    (replace && !same_primary) || serde_json::to_vec_pretty(&previous)? != content,
                    "此服务器已存在"
                );
                if previous.identity_key != bundle.identity_key {
                    identity_pin::verify_rotation_signature(
                        &previous.identity_key,
                        previous.identity_key_version,
                        &bundle.identity_key,
                        bundle.identity_key_version,
                        bundle
                            .rotation_signature
                            .as_ref()
                            .context("身份变更缺少轮换签名")?,
                    )?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    let primary_pin = draft["server_identity"]["fingerprint"]
        .as_str()
        .filter(|p| !p.is_empty());
    if same_primary || extra.is_some() {
        let pin = extra
            .and_then(|i| nodes[i]["fingerprint"].as_str())
            .or(primary_pin);
        if let Some(pin) = pin {
            ensure!(
                identity_pin::pins_match(pin, &bundle.identity_key)?,
                "导入的身份与已配置的指纹不匹配"
            );
        }
    }
    // Immutable filenames let a discarded draft coexist with the running bundle.
    use sha1::{Digest, Sha1};
    let relative = format!(
        "server-bundles/{}-{}.json",
        hex::encode(bundle.identity_key),
        hex::encode(Sha1::digest(&content))
    );
    let destination = base.join(&relative);
    if !destination.exists() {
        if let Err(error) =
            rvpn_core::crypto::key_files::write_new_file(&destination, &content, false)
        {
            if !destination.exists() {
                return Err(error.into());
            }
        }
    }
    ensure!(std::fs::read(destination)? == content, "公钥包文件冲突");
    let patch = if primary {
        let mut patch = json!({"server_address":url.as_str(),"prekey_bundle":relative,"sni_hostname":null,"server_public_key":null});
        if let Some(old_pin) = primary_pin.filter(|_| !same_primary) {
            let mut identity = draft["server_identity"].clone();
            identity["fingerprint"] = json!(fingerprint);
            patch["server_identity"] = identity;
            // Preserve pins inherited by existing routes when switching the default exit.
            for node in &mut nodes {
                if node["fingerprint"].is_null() {
                    node["fingerprint"] = json!(old_pin);
                }
            }
            patch["server"] = json!(nodes);
        }
        patch
    } else {
        if let Some(index) = extra {
            nodes[index]["prekey_bundle"] = json!(relative);
        } else {
            let host = url.host_str().unwrap();
            let mut name = host.to_string();
            let mut suffix = 2;
            while name == "default" || nodes.iter().any(|n| n["name"].as_str() == Some(&name)) {
                name = format!("{host}-{suffix}");
                suffix += 1;
            }
            nodes.push(
                json!({"name":name,"address":url.as_str(),"prekey_bundle":relative,
                "sni_hostname":null,"fingerprint":primary_pin.map(|_| &fingerprint)}),
            );
        }
        json!({"server":nodes})
    };
    Ok(json!({"patch":patch,"address":url.as_str(),"fingerprint":fingerprint}))
}

pub fn import(path: &Path, link: &str, replace: bool) -> Result<()> {
    let parent = path.parent().context("缺少配置目录")?;
    std::fs::create_dir_all(parent)?;
    let mut lock = fslock::LockFile::open(&path.with_extension("import.lock"))?;
    lock.lock()?;
    let is_json = match path.extension().and_then(|s| s.to_str()) {
        Some("toml") => false,
        Some("json") => true,
        _ => anyhow::bail!("需要 TOML 或 JSON 配置"),
    };
    let mut config: Value = match std::fs::read_to_string(path) {
        Ok(s) if is_json => serde_json::from_str(&s)?,
        Ok(s) => serde_json::to_value(toml::from_str::<toml::Value>(&s)?)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => return Err(e.into()),
    };
    let result = prepare(path, &config, link, replace)?;
    config
        .as_object_mut()
        .context("配置格式错误")?
        .extend(result["patch"].as_object().unwrap().clone());
    let _: crate::config::ClientConfig = serde_json::from_value(config.clone())?;
    let body = if is_json {
        serde_json::to_string_pretty(&config)?
    } else {
        toml::to_string_pretty(&crate::control_panel::without_nulls(config))?
    };
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    if let Ok(metadata) = path.metadata() {
        file.as_file().set_permissions(metadata.permissions())?;
    }
    file.write_all(body.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    println!(
        "已导入 {}  {}",
        result["address"].as_str().unwrap(),
        result["fingerprint"].as_str().unwrap()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvpn_core::crypto::X3DHResponder;

    fn make_link(address: &str, bundle: &X3DHPublicBundle) -> String {
        let body = json!({"v":1,"address":address,"bundle":bundle});
        format!(
            "rVPN://{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).unwrap())
        )
    }

    #[test]
    fn importing_into_toml_persists_and_preserves_other_nodes_and_settings() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.toml");
        let bundle = X3DHResponder::new().get_public_bundle();
        let first = make_link("wss://one.test/cw/ws", &bundle);
        let second = make_link("wss://two.test/cw/other/ws", &bundle);
        import(&path, &first, false).unwrap();
        let config = crate::config::ClientConfig::load(&path).unwrap();
        assert!(config.prekey_bundle.unwrap().is_file());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n[custom_settings]\nkeep = true\n")
            .unwrap();
        import(&path, &second, false).unwrap();
        let original = std::fs::read(&path).unwrap();
        assert!(import(&path, &second, false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        import(&path, &second, true).unwrap();
        let config = crate::config::ClientConfig::load(&path).unwrap();
        assert_eq!(config.server_address, "wss://two.test/cw/other/ws");
        assert_eq!(config.extra_servers.len(), 1);
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("keep = true"));
    }

    #[test]
    fn bad_signature_or_unverified_identity_change_preserves_config() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client.json");
        let url = "wss://one.test/cw/ws";
        let bundle = X3DHResponder::new().get_public_bundle();
        import(&path, &make_link(url, &bundle), false).unwrap();
        let mut other = X3DHResponder::new().get_public_bundle();
        let before = std::fs::read(&path).unwrap();
        assert!(import(&path, &make_link(url, &other), true).is_err());
        other.prekey_signature[0] ^= 1;
        assert!(import(&path, &make_link("wss://two.test/ws", &other), false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
