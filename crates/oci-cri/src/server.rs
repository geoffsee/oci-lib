// SPDX-License-Identifier: Apache-2.0

//! Daemon entry points.
//!
//! Linux serves CRI gRPC directly over the unix socket. Tests and embedded
//! agents can call [`serve_with_engine`] with an explicit [`Engine`].

use std::sync::Arc;

use crate::api::image_service_server::ImageServiceServer;
use crate::api::runtime_service_server::RuntimeServiceServer;
use crate::config::Config;
use crate::engine::Engine;
use crate::error::{Error, ErrorCode, Result};
use crate::service::CriService;

/// Serve CRI with the platform engine. Blocks until terminated.
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
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(crate::other::unsupported())
    }
}

/// Serve CRI on the configured unix socket with an explicit engine
/// (used by the guest agent and by tests). Runs until the runtime drops.
pub async fn serve_with_engine(config: Config, engine: Arc<dyn Engine>) -> Result<()> {
    let service = CriService::open(config.clone(), engine)?;
    serve_service(service, &config).await
}

/// Serve an already-built service on the config's unix socket, with the
/// streaming server alongside.
pub async fn serve_service(service: CriService, config: &Config) -> Result<()> {
    if let Some(parent) = config.socket.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(io_err)?;
    }
    let _ = tokio::fs::remove_file(&config.socket).await;
    let listener = tokio::net::UnixListener::bind(&config.socket).map_err(io_err)?;
    let streaming_addr = config.streaming_socket_addr()?;
    let streaming_state = service.streaming_state();
    let runtime_name = config.runtime_name.clone();
    let streaming = tokio::spawn(async move {
        if let Err(err) = crate::streaming::serve(streaming_state, streaming_addr).await {
            eprintln!("{runtime_name}: streaming server: {err}");
        }
    });
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
    let result = tonic::transport::Server::builder()
        .add_service(RuntimeServiceServer::new(service.clone_service()))
        .add_service(ImageServiceServer::new(service))
        .serve_with_incoming(incoming)
        .await
        .map_err(|err| Error::new(ErrorCode::Internal, format!("serving CRI: {err}"), ""));
    streaming.abort();
    result
}

fn io_err(err: std::io::Error) -> Error {
    Error::new(ErrorCode::Internal, err.to_string(), "")
}
