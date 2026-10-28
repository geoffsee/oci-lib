// SPDX-License-Identifier: Apache-2.0

//! Streaming Exec over the WebSocket channel protocol, end to end with the
//! fake engine: CRI `Exec` returns a URL, the client upgrades, and stdout
//! arrives as channel-1 messages.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use oci_cri::Config;
use oci_cri::api::runtime_service_client::RuntimeServiceClient;
use oci_cri::api::*;
use oci_cri::engine::Engine;
use oci_cri::test_support::FakeEngine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

async fn client(socket: PathBuf) -> RuntimeServiceClient<Channel> {
    let channel = Endpoint::from_static("http://localhost")
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&socket).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("connect");
    RuntimeServiceClient::new(channel)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streaming_exec_returns_stdout_on_channel_1() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("oci-cri.sock");
    let root = dir.path().join("root");
    let config = Config {
        socket: socket.clone(),
        root: root.clone(),
        state_root: dir.path().join("state"),
        sandbox_image: "fake/pause:latest".to_string(),
        ..Config::default()
    };
    let engine: Arc<dyn Engine> = Arc::new(FakeEngine::new(root));
    let server = tokio::spawn(async move {
        oci_cri::server::serve_with_engine(config, engine)
            .await
            .expect("serve");
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut runtime = client(socket).await;
    let sandbox = runtime
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "pod".into(),
                    uid: "uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                log_directory: dir.path().join("logs").to_string_lossy().into_owned(),
                ..PodSandboxConfig::default()
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("sandbox")
        .into_inner();
    // Image comes from the sandbox pull of the same fake registry name.
    let created = runtime
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox.pod_sandbox_id.clone(),
            config: Some(ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: "app".into(),
                    attempt: 1,
                }),
                image: Some(ImageSpec {
                    image: "fake/pause:latest".into(),
                    ..ImageSpec::default()
                }),
                command: vec!["/bin/sleep".into()],
                args: vec!["30".into()],
                ..ContainerConfig::default()
            }),
            sandbox_config: None,
        })
        .await
        .expect("create")
        .into_inner();
    runtime
        .start_container(StartContainerRequest {
            container_id: created.container_id.clone(),
        })
        .await
        .expect("start");
    let exec = runtime
        .exec(ExecRequest {
            container_id: created.container_id.clone(),
            cmd: vec!["/bin/echo".into(), "streamed-ok".into()],
            tty: false,
            stdin: false,
            stdout: true,
            stderr: true,
        })
        .await
        .expect("exec url")
        .into_inner();
    assert!(exec.url.starts_with("http://127.0.0.1:"), "{}", exec.url);

    // Minimal WebSocket client for the channel protocol.
    let address = exec
        .url
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_string();
    let path = exec.url.strip_prefix("http://").unwrap().to_string();
    let path = format!("/{}", path.split_once('/').map_or("", |x| x.1));
    let mut stream = tokio::net::TcpStream::connect(&address).await.expect("tcp");
    let key = base64_key();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: v4.channel.k8s.io\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "handshake eof");
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    assert!(text.contains("101"), "handshake: {text}");
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let mut pending = buf.split_off(header_end);
    let mut stdout = Vec::new();
    loop {
        // Parse one frame from pending, reading more as needed.
        let frame = loop {
            if pending.len() >= 2 {
                let mut len = u64::from(pending[1] & 0x7f);
                let mut at = 2usize;
                if len == 126 && pending.len() >= 4 {
                    len = u64::from(u16::from_be_bytes([pending[2], pending[3]]));
                    at = 4;
                }
                if pending.len() >= at + len as usize {
                    let payload = pending[at..at + len as usize].to_vec();
                    pending.drain(..at + len as usize);
                    break Some(payload);
                }
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break None,
                Ok(n) => pending.extend_from_slice(&chunk[..n]),
            }
        };
        let Some(payload) = frame else { break };
        if payload.is_empty() {
            continue;
        }
        if payload[0] == 1 {
            stdout.extend_from_slice(&payload[1..]);
        }
        if String::from_utf8_lossy(&stdout).contains("streamed-ok") {
            break;
        }
    }
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "streamed-ok");

    runtime
        .stop_container(StopContainerRequest {
            container_id: created.container_id.clone(),
            timeout: 0,
        })
        .await
        .expect("stop");
    runtime
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox.pod_sandbox_id,
        })
        .await
        .expect("remove sandbox");
    server.abort();
}

fn base64_key() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([7u8; 16])
}
