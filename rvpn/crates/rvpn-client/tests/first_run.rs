//! CLI first-run initialization without a VPN connection or existing keys.
use std::process::Command;

#[tokio::test]
async fn control_panel_remains_available_after_vpn_startup_failure() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let directory = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = directory.path().join("client.toml");
    std::fs::write(directory.path().join("invalid.key"), "invalid identity").unwrap();
    std::fs::write(&config, format!("identity_key_file = './invalid.key'\ndata_dir = './data'\n[logging]\ndirectory = './logs'\n[dashboard]\nenabled = true\nlisten_address = '{address}'\n")).unwrap();
    struct Process(std::process::Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Process(
        Command::new(env!("CARGO_BIN_EXE_rvpn"))
            .args(["-c", config.to_str().unwrap()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "Client exited before configuration could be repaired"
            );
            let mut request = format!("ws://{address}/ws").into_client_request().unwrap();
            request
                .headers_mut()
                .insert("origin", format!("http://{address}").parse().unwrap());
            if let Ok((mut ws, _)) = tokio_tungstenite::connect_async(request).await {
                loop {
                    let event: serde_json::Value =
                        serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap())
                            .unwrap();
                    if event["type"] == "stats" && event["data"]["runtime_error"].is_string() {
                        assert!(event["data"]["runtime_error"]
                            .as_str()
                            .unwrap()
                            .contains("identity"));
                        return;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(!directory.path().join("logs").exists());
}

#[test]
fn client_startup_errors_use_stderr_without_creating_log_files() {
    for enabled in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let config_dir = directory.path().join("config");
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::write(config_dir.join("invalid.key"), "invalid identity").unwrap();
        let config = config_dir.join("client.toml");
        std::fs::write(&config, format!(
            "identity_key_file = './invalid.key'\ndata_dir = './data'\n[logging]\nfile_enabled = {enabled}\ndirectory = './logs'\nlevel = 'off'\n"
        )).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_rvpn"))
            .args(["-c", config.to_str().unwrap()])
            .current_dir(std::env::temp_dir())
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Client terminated:"), "{stderr}");
        assert!(stderr.contains("identity"), "{stderr}");
        assert!(!config_dir.join("logs").exists());
        assert!(!directory.path().join("logs").exists());
    }
}

#[test]
fn example_and_legacy_fingerprints_parse() {
    let example = include_str!("../../../../config/client.toml.example");
    for config in [example.to_owned(), example.replace("\"Chrome\"", "\"chrome\"")] {
        let config: rvpn_client::config::ClientConfig = toml::from_str(&config).unwrap();
        assert_eq!(config.tls_fingerprint, rvpn_client::TlsFingerprint::Chrome);
    }
}

#[test]
fn client_creates_identity_but_never_invents_server_bundle() {
    let dir = tempfile::tempdir().unwrap();
    // Run a private copy to check that a failed start never opens the default log.
    let binary = dir.path().join(
        std::path::Path::new(env!("CARGO_BIN_EXE_rvpn"))
            .file_name()
            .unwrap(),
    );
    std::fs::copy(env!("CARGO_BIN_EXE_rvpn"), &binary).unwrap();
    let config = dir.path().join("client.toml");
    std::fs::write(&config, "tls_fingerprint = 'invalid'\n").unwrap();
    let mut command = Command::new(&binary);
    command.arg("-c").arg(&config);
    let output = run_private_copy(&mut command).unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("TOML parse error"), "{stderr}");
    assert!(stderr.contains("tls_fingerprint"), "{stderr}");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    std::fs::write(&config, "identity_key_file = './keys/identity.key'\nprekey_bundle = './missing-server-bundle.json'\ndata_dir = './data'\n").unwrap();
    let key_path = dir.path().join("keys/identity.key");
    let mut previous = None;
    for run in 0..2 {
        let mut command = Command::new(&binary);
        command
            .current_dir(std::env::temp_dir())
            .arg("-c")
            .arg(&config)
            .arg("-v");
        let output = run_private_copy(&mut command).unwrap();
        assert!(
            !output.status.success(),
            "Missing server bundle should stop startup"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("client cannot generate it"), "{stderr}");
        assert_eq!(stderr.matches("Client terminated:").count(), 1);
        assert!(stdout.contains("Client public identity (Ed25519, base64)"));
        assert!(stdout.contains("Client identity fingerprint: ik:1:"));
        assert!(stdout.contains(if run == 0 {
            "Client identity key generated:"
        } else {
            "Client identity key loaded:"
        }));
        let key = std::fs::read_to_string(&key_path).unwrap();
        assert!(!std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .any(|path| path.extension().is_some_and(|ext| ext == "log")));
        assert!(
            !stdout.contains(key.lines().nth(2).unwrap()) && !stderr.contains(key.lines().nth(2).unwrap()),
            "Private key leaked into startup output"
        );
        if let Some(before) = &previous {
            assert_eq!(&key, before);
        }
        previous = Some(key);
        assert!(!dir.path().join("missing-server-bundle.json").exists());
    }
}

// A runner filesystem can briefly report ETXTBSY after copying a binary.
// Preserve the executable-relative log check and retry only failed launches.
fn run_private_copy(command: &mut Command) -> std::io::Result<std::process::Output> {
    use std::io::ErrorKind;
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match command.output() {
            Err(error)
                if error.kind() == ErrorKind::ExecutableFileBusy && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            result => return result,
        }
    }
}
