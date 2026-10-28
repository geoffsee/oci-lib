//! The embedding API owns both listeners and propagates startup failures.
use std::sync::Arc;
use std::time::Duration;

use oci_cri::{Config, test_support::FakeEngine};

#[tokio::test]
async fn shutdown_releases_socket_and_streaming_port() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cri.sock");
    let root = dir.path().join("root");
    let service = oci_cri::CriService::open(
        Config {
            socket: socket.clone(),
            root: root.clone(),
            state_root: dir.path().join("state"),
            ..Config::default()
        },
        Arc::new(FakeEngine::new(root)),
    )
    .unwrap();
    let state = service.streaming_state();
    let config = service.config().clone();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        oci_cri::server::serve_service_until(service, &config, async {
            let _ = stopped.await;
        })
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !socket.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let address = state.base_url().unwrap();
    let address = address.strip_prefix("http://").unwrap();
    let mut connection = tokio::net::TcpStream::connect(address).await.unwrap();
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!socket.exists());
    let _listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let mut byte = [0u8];
    use tokio::io::AsyncReadExt;
    let read = tokio::time::timeout(Duration::from_secs(5), connection.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[tokio::test]
async fn streaming_bind_failure_does_not_publish_cri_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cri.sock");
    let root = dir.path().join("root");
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = Config {
        socket: socket.clone(),
        root: root.clone(),
        state_root: dir.path().join("state"),
        streaming_port: occupied.local_addr().unwrap().port(),
        ..Config::default()
    };
    let error = oci_cri::server::serve_with_engine_until(
        config,
        Arc::new(FakeEngine::new(root)),
        std::future::pending(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), oci_cri::ErrorCode::Prerequisite);
    assert!(!socket.exists());
}
