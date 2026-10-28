// SPDX-License-Identifier: Apache-2.0

//! Shared bootstrap for oci-cri integration tests (fake engine + unix socket).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oci_cri::Config;
use oci_cri::api::image_service_client::ImageServiceClient;
use oci_cri::api::runtime_service_client::RuntimeServiceClient;
use oci_cri::api::*;
use oci_cri::engine::Engine;
use oci_cri::test_support::FakeEngine;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub struct Harness {
    pub dir: tempfile::TempDir,
    pub runtime: RuntimeServiceClient<Channel>,
    pub images: ImageServiceClient<Channel>,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("oci-cri.sock");
        let root = dir.path().join("root");
        let config = Config {
            socket: socket.clone(),
            root: root.clone(),
            state_root: dir.path().join("state"),
            sandbox_image: "fake/pause:latest".to_string(),
            streaming_address: "127.0.0.1".to_string(),
            streaming_port: 0,
            ..Config::default()
        };
        let engine: Arc<dyn Engine> = Arc::new(FakeEngine::new(root));
        let server_config = config.clone();
        let server = tokio::spawn(async move {
            oci_cri::server::serve_with_engine(server_config, engine)
                .await
                .expect("serve");
        });
        wait_for_socket(&socket).await;
        let (runtime, images) = clients(socket).await;
        Self {
            dir,
            runtime,
            images,
            server,
        }
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.dir.path().join("logs")
    }

    pub async fn run_sandbox(&mut self, name: &str, labels: HashMap<String, String>) -> String {
        let response = self
            .runtime
            .run_pod_sandbox(RunPodSandboxRequest {
                config: Some(PodSandboxConfig {
                    metadata: Some(PodSandboxMetadata {
                        name: name.into(),
                        uid: format!("uid-{name}"),
                        namespace: "default".into(),
                        attempt: 1,
                    }),
                    hostname: name.into(),
                    log_directory: self.logs_dir().to_string_lossy().into_owned(),
                    labels,
                    linux: Some(LinuxPodSandboxConfig {
                        security_context: Some(LinuxSandboxSecurityContext {
                            namespace_options: Some(NamespaceOption {
                                network: NamespaceMode::Pod as i32,
                                ..NamespaceOption::default()
                            }),
                            ..LinuxSandboxSecurityContext::default()
                        }),
                        ..LinuxPodSandboxConfig::default()
                    }),
                    ..PodSandboxConfig::default()
                }),
                runtime_handler: String::new(),
            })
            .await
            .expect("run sandbox")
            .into_inner();
        response.pod_sandbox_id
    }

    pub async fn create_and_start(
        &mut self,
        sandbox_id: &str,
        name: &str,
        command: Vec<String>,
        args: Vec<String>,
        labels: HashMap<String, String>,
    ) -> String {
        let created = self
            .runtime
            .create_container(CreateContainerRequest {
                pod_sandbox_id: sandbox_id.to_string(),
                config: Some(ContainerConfig {
                    metadata: Some(ContainerMetadata {
                        name: name.into(),
                        attempt: 1,
                    }),
                    image: Some(ImageSpec {
                        image: "fake/app:latest".into(),
                        ..ImageSpec::default()
                    }),
                    command,
                    args,
                    labels,
                    log_path: format!("{name}/0.log"),
                    ..ContainerConfig::default()
                }),
                sandbox_config: None,
            })
            .await
            .expect("create")
            .into_inner();
        self.runtime
            .start_container(StartContainerRequest {
                container_id: created.container_id.clone(),
            })
            .await
            .expect("start");
        created.container_id
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn clients(socket: PathBuf) -> (RuntimeServiceClient<Channel>, ImageServiceClient<Channel>) {
    let channel = Endpoint::from_static("http://localhost")
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&socket).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("connect to CRI socket");
    (
        RuntimeServiceClient::new(channel.clone()),
        ImageServiceClient::new(channel),
    )
}

async fn wait_for_socket(path: &Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("socket {} never appeared", path.display());
}
