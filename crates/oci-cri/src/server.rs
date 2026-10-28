// SPDX-License-Identifier: Apache-2.0

//! Daemon entry points.
//!
//! Linux serves CRI gRPC directly over the unix socket. Tests and embedded
//! agents can call [`serve_with_engine`] with an explicit [`Engine`].

use std::future::Future;
use std::sync::Arc;

use crate::api::image_service_server::ImageServiceServer;
use crate::api::runtime_service_server::RuntimeServiceServer;
use crate::config::Config;
use crate::engine::Engine;
use crate::error::{Error, ErrorCode, Result};
use crate::service::CriService;

/// Serve the native Linux engine on the caller's executor until shutdown.
/// Call [`crate::startup`] before creating threads. This entry point does not
/// boot a macOS VM; use [`serve`] for the VM transport.
#[cfg(target_os = "linux")]
pub async fn serve_until(config: Config, shutdown: impl Future<Output = ()>) -> Result<()> {
    config.validate()?;
    crate::linux::open()?;
    struct EngineGuard;
    impl Drop for EngineGuard {
        fn drop(&mut self) {
            let _ = crate::linux::shutdown();
        }
    }
    let _guard = EngineGuard;
    let engine = Arc::new(crate::linux::LinuxEngine::new(
        config.root.clone(),
        config.state_root.clone(),
    ));
    serve_with_engine_until(config, engine, shutdown).await
}

/// Serve CRI with the platform engine. Blocks until terminated.
///
/// On Linux this runs gRPC in-process. On macOS with the `vm` feature it boots
/// the embedded Linux guest and proxies the configured unix socket over
/// virtio-vsock.
pub fn serve(config: Config) -> Result<()> {
    config.validate()?;
    #[cfg(target_os = "linux")]
    {
        crate::linux::open()?;
        let engine: Arc<dyn Engine> = Arc::new(crate::linux::LinuxEngine::new(
            config.root.clone(),
            config.state_root.clone(),
        ));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| Error::new(ErrorCode::Internal, err.to_string(), ""))?;
        let result = runtime.block_on(serve_with_engine(config, engine));
        let _ = crate::linux::shutdown();
        result
    }
    #[cfg(rok_vm)]
    {
        crate::macos::serve(config)
    }
    #[cfg(not(any(target_os = "linux", rok_vm)))]
    {
        let _ = config;
        Err(crate::other::unsupported())
    }
}

/// Serve CRI on the configured unix socket with an explicit engine
/// (used by the guest agent and by tests). Runs until the runtime drops.
pub async fn serve_with_engine(config: Config, engine: Arc<dyn Engine>) -> Result<()> {
    serve_with_engine_until(config, engine, std::future::pending()).await
}

/// Serve an explicit engine until shutdown is requested. Stops accepting CRI
/// requests, drains in-flight RPCs, and closes the streaming server. Workload
/// termination remains the caller's responsibility.
pub async fn serve_with_engine_until(
    config: Config,
    engine: Arc<dyn Engine>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    config.validate()?;
    let service = CriService::open(config.clone(), engine)?;
    serve_service_until(service, &config, shutdown).await
}

/// Serve an already-built service on the config's unix socket, with the
/// streaming server alongside.
pub async fn serve_service(service: CriService, config: &Config) -> Result<()> {
    serve_service_until(service, config, std::future::pending()).await
}

/// Serve a service with cooperative shutdown. Streaming bind failures are
/// returned before exposing the CRI socket, so readiness includes streaming.
pub async fn serve_service_until(
    service: CriService,
    config: &Config,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    config.validate()?;
    let streaming_state = service.streaming_state();
    let streaming_listener =
        crate::streaming::bind(&streaming_state, config.streaming_socket_addr()?).await?;
    if let Some(parent) = config.socket.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(io_err)?;
    }
    let _ = tokio::fs::remove_file(&config.socket).await;
    let listener = tokio::net::UnixListener::bind(&config.socket).map_err(io_err)?;
    let streaming = crate::streaming::serve_listener(streaming_state, streaming_listener);
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
    let grpc = tonic::transport::Server::builder()
        .add_service(RuntimeServiceServer::new(service.clone_service()))
        .add_service(ImageServiceServer::new(service))
        .serve_with_incoming_shutdown(incoming, shutdown);
    let result = tokio::select! {
        result = grpc => result.map_err(|err| Error::new(ErrorCode::Internal, format!("serving CRI: {err}"), "")),
        result = streaming => result,
    };
    let _ = tokio::fs::remove_file(&config.socket).await;
    result
}

fn io_err(err: std::io::Error) -> Error {
    Error::new(ErrorCode::Internal, err.to_string(), "")
}
