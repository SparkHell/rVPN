//! Exercise desktop startup and setup through the embedded panel's WebSocket.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn start(directory: &Path, command: &mut Command) -> (Process, SocketAddr, Socket, Value) {
    let stdout = directory.join("stdout");
    let stderr = directory.join("stderr");
    command
        .stdout(Stdio::from(std::fs::File::create(&stdout).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(&stderr).unwrap()));
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut process = Process(loop {
        match command.spawn() {
            Ok(child) => break child,
            // A runner can briefly report ETXTBSY for a freshly copied binary.
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => panic!("{error}"),
        }
    });
    let (address, socket, session) = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "{}",
                std::fs::read_to_string(&stderr).unwrap()
            );
            let output = std::fs::read_to_string(&stdout).unwrap_or_default();
            if let Some(address) = output.lines().find_map(|line| {
                line.split_once("http://")?
                    .1
                    .strip_suffix('/')?
                    .parse::<SocketAddr>()
                    .ok()
            }) {
                let mut request = format!("ws://{address}/ws").into_client_request().unwrap();
                request
                    .headers_mut()
                    .insert("origin", format!("http://{address}").parse().unwrap());
                if let Ok((mut socket, _)) = tokio_tungstenite::connect_async(request).await {
                    let session = next(&mut socket, "session").await;
                    return (address, socket, session["data"].clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    (process, address, socket, session)
}

async fn next(socket: &mut Socket, kind: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let event: Value =
                serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            if event["type"] == kind {
                return event;
            }
        }
    })
    .await
    .unwrap()
}

async fn rpc(socket: &mut Socket, request: Value) -> Value {
    socket
        .send(Message::Text(request.to_string()))
        .await
        .unwrap();
    next(socket, "response").await
}

fn free_address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

#[tokio::test]
async fn fresh_example_and_broken_configs_can_import_apply_and_export() {
    let example = include_str!("../../../../config/client.toml.example");
    let legacy = format!(
        "server_address = 'wss://vpn.example.com/api/v1/ws'\nprekey_bundle = './prekey-bundle.json'\n{example}"
    );
    let bundle = rvpn_core::crypto::X3DHResponder::new().get_public_bundle();
    let link_data = json!({"v":1,"address":"wss://127.0.0.1/cw/ws","bundle":bundle});
    let link = format!(
        "rVPN://{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&link_data).unwrap())
    );
    for (filename, original, broken, occupy_panel) in [
        ("client.toml", None, false, false),
        ("client.toml", Some(example), false, false),
        ("client.toml", Some(legacy.as_str()), false, true),
        ("client.toml", Some("[bad"), true, false),
        (
            "client.json",
            Some(r#"{"socks5":{"listen_address":42}}"#),
            true,
            false,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(filename);
        let binary = Path::new(env!("CARGO_BIN_EXE_rvpn"));
        let panel = free_address();
        let occupied_panel = occupy_panel.then(|| std::net::TcpListener::bind(panel).unwrap());
        let original = original.map(|contents| {
            if occupy_panel {
                contents.replace("127.0.0.1:9800", &panel.to_string())
            } else {
                contents.to_owned()
            }
        });
        let mut command = if let Some(contents) = &original {
            std::fs::write(&path, contents).unwrap();
            let mut command = Command::new(binary);
            command.arg("-c").arg(&path);
            command
        } else {
            let copy = directory.path().join(binary.file_name().unwrap());
            std::fs::copy(binary, &copy).unwrap();
            Command::new(copy)
        };
        if occupied_panel.is_none() {
            command.args(["--dashboard-listen", &panel.to_string()]);
        }
        command.current_dir(std::env::temp_dir());
        let (mut process, address, mut socket, session) =
            start(directory.path(), &mut command).await;
        if occupy_panel {
            assert_ne!(address, panel);
            assert!(address.ip().is_loopback());
            assert_eq!(
                session["config"]["dashboard"]["listen_address"],
                address.to_string()
            );
        } else {
            assert_eq!(address, panel);
        }
        assert_eq!(session["config_error"], broken);
        assert_eq!(session["runtime"]["awaiting_server_import"], true);
        assert!(!directory.path().join("identity.key").exists());
        assert!(!directory.path().join("prekey-bundle.json").exists());
        assert_eq!(
            rpc(&mut socket, json!({"id":1,"method":"server.export"})).await["ok"],
            false
        );
        let before = std::fs::read(&path).unwrap();
        if let Some(original) = original {
            assert_eq!(before, original.as_bytes());
        } else {
            assert!(!before.is_empty());
        }
        let mut config = session["config"].clone();
        let imported = rpc(
            &mut socket,
            json!({"id":2,"method":"server.import","config":config,"link":link}),
        )
        .await;
        assert_eq!(imported["ok"], true, "{imported}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        config
            .as_object_mut()
            .unwrap()
            .extend(imported["data"]["patch"].as_object().unwrap().clone());
        let socks = free_address();
        let blocked = std::net::TcpListener::bind(socks).unwrap();
        config["socks5"]["listen_address"] = json!(socks.to_string());
        config["http_proxy"]["enabled"] = json!(false);
        config["dns_proxy"]["enabled"] = json!(false);
        config["split_tunnel"]["enabled"] = json!(false);
        config["data_dir"] = json!("./data");
        config["logging"]["directory"] = json!("./logs");
        let save =
            json!({"id":3,"method":"config.save","config":config,"revision":session["revision"]});
        let rejected = rpc(&mut socket, save.clone()).await;
        assert_eq!(rejected["ok"], false, "{rejected}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(blocked);
        let saved = rpc(&mut socket, save).await;
        assert_eq!(saved["ok"], true, "{saved}");
        assert_eq!(saved["data"]["config_error"], false);
        assert_eq!(saved["data"]["runtime"]["awaiting_server_import"], false);
        assert!(TcpStream::connect(socks).await.is_ok());
        assert!(process.0.try_wait().unwrap().is_none());
        let exported = rpc(&mut socket, json!({"id":4,"method":"server.export"})).await;
        assert_eq!(exported["ok"], true, "{exported}");
        let exported = exported["data"]["link"].as_str().unwrap();
        let decoded: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(exported.strip_prefix("rVPN://").unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(decoded, link_data);
        let reimported = rpc(
            &mut socket,
            json!({"id":5,"method":"server.import","config":session["config"],"link":exported}),
        )
        .await;
        assert_eq!(reimported["ok"], true, "{reimported}");
        if !broken {
            let stderr = std::fs::read_to_string(directory.path().join("stderr")).unwrap();
            assert!(!stderr.contains("VPN failed to start"), "{stderr}");
        }
    }
}

#[tokio::test]
async fn startup_errors_open_local_recovery_even_when_dashboard_is_disabled() {
    for (contents, expected) in [
        ("identity_key_file = './invalid.key'\n", "identity"),
        ("identity_key_file = './keys/identity.key'\nprekey_bundle = './missing-server-bundle.json'\n", "client cannot generate it"),
        ("[logging]\nlevel = 'invalid'\n", "日志配置无效"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client.toml");
        std::fs::write(directory.path().join("invalid.key"), "invalid identity").unwrap();
        std::fs::write(&path, format!("data_dir = './data'\n{contents}")).unwrap();
        let (mut process, panel, mut socket, _) = start(
            directory.path(), Command::new(env!("CARGO_BIN_EXE_rvpn")).arg("-c").arg(&path).arg("-v")
        ).await;
        assert!(panel.ip().is_loopback());
        let stats = next(&mut socket, "stats").await;
        let error = stats["data"]["runtime_error"].as_str().unwrap();
        assert!(error.contains(expected), "{error}");
        assert!(process.0.try_wait().unwrap().is_none());
        assert!(!directory.path().join("logs").exists());
        assert!(!directory.path().join("missing-server-bundle.json").exists());
        if expected.contains("generate") {
            let key = std::fs::read_to_string(directory.path().join("keys/identity.key")).unwrap();
            let stdout = std::fs::read_to_string(directory.path().join("stdout")).unwrap();
            let stderr = std::fs::read_to_string(directory.path().join("stderr")).unwrap();
            assert!(stdout.contains("Client identity fingerprint: ik:1:"));
            assert!(!stdout.contains(key.lines().nth(2).unwrap()) && !stderr.contains(key.lines().nth(2).unwrap()));
        }
    }
}

#[test]
fn example_and_legacy_fingerprints_parse() {
    let example = include_str!("../../../../config/client.toml.example");
    for config in [
        example.to_owned(),
        example.replace("\"Chrome\"", "\"chrome\""),
    ] {
        let config: rvpn_client::config::ClientConfig = toml::from_str(&config).unwrap();
        assert_eq!(config.tls_fingerprint, rvpn_client::TlsFingerprint::Chrome);
    }
}
