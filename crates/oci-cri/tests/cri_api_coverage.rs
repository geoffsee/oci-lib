// SPDX-License-Identifier: Apache-2.0

//! Broader CRI API coverage over the fake engine: image RPCs, list filters,
//! status/runtime config, error shapes, multi-container sandboxes, and
//! idempotent teardown paths the happy-path lifecycle test does not hit.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use oci_cri::api::*;
use tonic::Code;

use common::Harness;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_version_and_runtime_config() {
    let mut h = Harness::start().await;

    let version = h
        .runtime
        .version(VersionRequest {
            version: "v1".into(),
        })
        .await
        .expect("version")
        .into_inner();
    assert_eq!(version.runtime_name, "oci-cri");
    assert_eq!(version.runtime_api_version, "v1");

    let status = h
        .runtime
        .status(StatusRequest { verbose: true })
        .await
        .expect("status")
        .into_inner();
    let conditions = &status.status.as_ref().unwrap().conditions;
    assert!(
        conditions
            .iter()
            .any(|c| c.r#type == "RuntimeReady" && c.status)
    );
    assert_eq!(
        status.info.get("runtime").map(String::as_str),
        Some("oci-cri")
    );

    h.runtime
        .update_runtime_config(UpdateRuntimeConfigRequest {
            runtime_config: Some(RuntimeConfig {
                network_config: Some(NetworkConfig {
                    pod_cidr: "10.244.0.0/16".into(),
                }),
            }),
        })
        .await
        .expect("update runtime config");

    let status = h
        .runtime
        .status(StatusRequest { verbose: true })
        .await
        .expect("status after cidr")
        .into_inner();
    assert_eq!(
        status.info.get("podCIDR").map(String::as_str),
        Some("10.244.0.0/16")
    );

    let runtime_config = h
        .runtime
        .runtime_config(RuntimeConfigRequest {})
        .await
        .expect("runtime config")
        .into_inner();
    assert!(runtime_config.linux.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn image_service_pull_status_list_remove_and_fs_info() {
    let mut h = Harness::start().await;

    let pulled = h
        .images
        .pull_image(PullImageRequest {
            image: Some(ImageSpec {
                image: "fake/web:1".into(),
                ..ImageSpec::default()
            }),
            auth: None,
            sandbox_config: None,
        })
        .await
        .expect("pull")
        .into_inner();
    assert!(
        pulled.image_ref.contains("fake/web"),
        "{}",
        pulled.image_ref
    );

    let missing_pull = h
        .images
        .pull_image(PullImageRequest {
            image: None,
            auth: None,
            sandbox_config: None,
        })
        .await
        .expect_err("pull without image");
    assert_eq!(missing_pull.code(), Code::InvalidArgument);

    let status = h
        .images
        .image_status(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "fake/web:1".into(),
                ..ImageSpec::default()
            }),
            verbose: true,
        })
        .await
        .expect("image status")
        .into_inner();
    assert!(status.image.is_some());
    assert!(status.info.contains_key("image"));

    let absent = h
        .images
        .image_status(ImageStatusRequest {
            image: Some(ImageSpec {
                image: "does-not-exist:latest".into(),
                ..ImageSpec::default()
            }),
            verbose: false,
        })
        .await
        .expect("absent status")
        .into_inner();
    assert!(absent.image.is_none());

    h.images
        .pull_image(PullImageRequest {
            image: Some(ImageSpec {
                image: "fake/other:2".into(),
                ..ImageSpec::default()
            }),
            auth: None,
            sandbox_config: None,
        })
        .await
        .expect("pull other");

    let listed = h
        .images
        .list_images(ListImagesRequest { filter: None })
        .await
        .expect("list")
        .into_inner();
    assert!(listed.images.len() >= 2);

    let filtered = h
        .images
        .list_images(ListImagesRequest {
            filter: Some(ImageFilter {
                image: Some(ImageSpec {
                    image: "fake/web:1".into(),
                    ..ImageSpec::default()
                }),
            }),
        })
        .await
        .expect("filtered list")
        .into_inner();
    assert_eq!(filtered.images.len(), 1);
    assert!(
        filtered.images[0]
            .repo_tags
            .iter()
            .any(|t| t == "fake/web:1")
    );

    let fs = h
        .images
        .image_fs_info(ImageFsInfoRequest {})
        .await
        .expect("fs info")
        .into_inner();
    assert!(!fs.image_filesystems.is_empty());

    h.images
        .remove_image(RemoveImageRequest {
            image: Some(ImageSpec {
                image: "fake/web:1".into(),
                ..ImageSpec::default()
            }),
        })
        .await
        .expect("remove");
    // Idempotent remove of a missing image.
    h.images
        .remove_image(RemoveImageRequest {
            image: Some(ImageSpec {
                image: "fake/web:1".into(),
                ..ImageSpec::default()
            }),
        })
        .await
        .expect("remove again");

    let after = h
        .images
        .list_images(ListImagesRequest {
            filter: Some(ImageFilter {
                image: Some(ImageSpec {
                    image: "fake/web:1".into(),
                    ..ImageSpec::default()
                }),
            }),
        })
        .await
        .expect("list after remove")
        .into_inner();
    assert!(after.images.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_filters_and_not_found_errors() {
    let mut h = Harness::start().await;

    h.images
        .pull_image(PullImageRequest {
            image: Some(ImageSpec {
                image: "fake/app:latest".into(),
                ..ImageSpec::default()
            }),
            auth: None,
            sandbox_config: None,
        })
        .await
        .expect("pull app");

    let front = h
        .run_sandbox("front", HashMap::from([("tier".into(), "front".into())]))
        .await;
    let back = h
        .run_sandbox("back", HashMap::from([("tier".into(), "back".into())]))
        .await;

    let web = h
        .create_and_start(
            &front,
            "web",
            vec!["/bin/sleep".into()],
            vec!["30".into()],
            HashMap::from([("app".into(), "web".into())]),
        )
        .await;
    let _worker = h
        .create_and_start(
            &back,
            "worker",
            vec!["/bin/sleep".into()],
            vec!["30".into()],
            HashMap::from([("app".into(), "worker".into())]),
        )
        .await;

    let by_label = h
        .runtime
        .list_pod_sandbox(ListPodSandboxRequest {
            filter: Some(PodSandboxFilter {
                label_selector: HashMap::from([("tier".into(), "front".into())]),
                ..PodSandboxFilter::default()
            }),
        })
        .await
        .expect("sandbox label filter")
        .into_inner();
    assert_eq!(by_label.items.len(), 1);
    assert_eq!(by_label.items[0].id, front);

    let by_sandbox = h
        .runtime
        .list_containers(ListContainersRequest {
            filter: Some(ContainerFilter {
                pod_sandbox_id: front.clone(),
                ..ContainerFilter::default()
            }),
        })
        .await
        .expect("container sandbox filter")
        .into_inner();
    assert_eq!(by_sandbox.containers.len(), 1);
    assert_eq!(by_sandbox.containers[0].id, web);

    let running = h
        .runtime
        .list_containers(ListContainersRequest {
            filter: Some(ContainerFilter {
                state: Some(ContainerStateValue {
                    state: ContainerState::ContainerRunning as i32,
                }),
                ..ContainerFilter::default()
            }),
        })
        .await
        .expect("running filter")
        .into_inner();
    assert!(running.containers.len() >= 2);

    let missing = h
        .runtime
        .container_status(ContainerStatusRequest {
            container_id: "does-not-exist".into(),
            verbose: false,
        })
        .await
        .expect_err("missing container");
    assert_eq!(missing.code(), Code::NotFound);

    let missing_sb = h
        .runtime
        .pod_sandbox_status(PodSandboxStatusRequest {
            pod_sandbox_id: "does-not-exist".into(),
            verbose: false,
        })
        .await
        .expect_err("missing sandbox");
    assert_eq!(missing_sb.code(), Code::NotFound);

    let bad_create = h
        .runtime
        .create_container(CreateContainerRequest {
            pod_sandbox_id: "missing-sandbox".into(),
            config: Some(ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: "x".into(),
                    attempt: 1,
                }),
                image: Some(ImageSpec {
                    image: "fake/app:latest".into(),
                    ..ImageSpec::default()
                }),
                command: vec!["/bin/true".into()],
                ..ContainerConfig::default()
            }),
            sandbox_config: None,
        })
        .await
        .expect_err("create without sandbox");
    assert_eq!(bad_create.code(), Code::NotFound);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_container_stats_resources_logs_and_teardown() {
    let mut h = Harness::start().await;

    h.images
        .pull_image(PullImageRequest {
            image: Some(ImageSpec {
                image: "fake/app:latest".into(),
                ..ImageSpec::default()
            }),
            auth: None,
            sandbox_config: None,
        })
        .await
        .expect("pull");

    let sandbox_id = h.run_sandbox("multi", HashMap::new()).await;
    let a = h
        .create_and_start(
            &sandbox_id,
            "a",
            vec!["/bin/sh".into()],
            vec!["-c".into(), "echo alpha; sleep 30".into()],
            HashMap::new(),
        )
        .await;
    let b = h
        .create_and_start(
            &sandbox_id,
            "b",
            vec!["/bin/sleep".into()],
            vec!["30".into()],
            HashMap::new(),
        )
        .await;

    let sb_status = h
        .runtime
        .pod_sandbox_status(PodSandboxStatusRequest {
            pod_sandbox_id: sandbox_id.clone(),
            verbose: true,
        })
        .await
        .expect("sandbox status")
        .into_inner();
    assert!(sb_status.containers_statuses.len() >= 2);
    assert!(!sb_status.info.is_empty());

    let stats = h
        .runtime
        .list_container_stats(ListContainerStatsRequest {
            filter: Some(ContainerStatsFilter {
                pod_sandbox_id: sandbox_id.clone(),
                ..ContainerStatsFilter::default()
            }),
        })
        .await
        .expect("list stats")
        .into_inner();
    assert!(stats.stats.len() >= 2);

    let pod_stats = h
        .runtime
        .pod_sandbox_stats(PodSandboxStatsRequest {
            pod_sandbox_id: sandbox_id.clone(),
        })
        .await
        .expect("pod stats")
        .into_inner();
    assert!(pod_stats.stats.is_some());

    h.runtime
        .update_container_resources(UpdateContainerResourcesRequest {
            container_id: a.clone(),
            linux: Some(LinuxContainerResources {
                memory_limit_in_bytes: 64 * 1024 * 1024,
                cpu_shares: 512,
                ..LinuxContainerResources::default()
            }),
            windows: None,
            annotations: HashMap::new(),
        })
        .await
        .expect("update resources");

    // Wait for log lines, then reopen.
    let log_path = h.logs_dir().join("a/0.log");
    for _ in 0..50 {
        if std::fs::read_to_string(&log_path)
            .map(|t| t.contains("alpha"))
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    h.runtime
        .reopen_container_log(ReopenContainerLogRequest {
            container_id: a.clone(),
        })
        .await
        .expect("reopen log");

    let exec_fail = h
        .runtime
        .exec_sync(ExecSyncRequest {
            container_id: a.clone(),
            cmd: vec!["/bin/sh".into(), "-c".into(), "exit 7".into()],
            timeout: 5,
        })
        .await
        .expect("exec failing command")
        .into_inner();
    assert_eq!(exec_fail.exit_code, 7);

    let checkpoint = h
        .runtime
        .checkpoint_container(CheckpointContainerRequest {
            container_id: a.clone(),
            location: h.dir.path().join("ckpt").to_string_lossy().into_owned(),
            timeout: 1,
        })
        .await
        .expect_err("checkpoint unsupported");
    assert_eq!(checkpoint.code(), Code::Unimplemented);

    // Stop once, then stop again (idempotent).
    h.runtime
        .stop_container(StopContainerRequest {
            container_id: a.clone(),
            timeout: 1,
        })
        .await
        .expect("stop a");
    h.runtime
        .stop_container(StopContainerRequest {
            container_id: a.clone(),
            timeout: 1,
        })
        .await
        .expect("stop a again");

    let exited = h
        .runtime
        .list_containers(ListContainersRequest {
            filter: Some(ContainerFilter {
                id: a.clone(),
                state: Some(ContainerStateValue {
                    state: ContainerState::ContainerExited as i32,
                }),
                ..ContainerFilter::default()
            }),
        })
        .await
        .expect("exited filter")
        .into_inner();
    assert_eq!(exited.containers.len(), 1);

    // Removing the sandbox cleans up remaining containers.
    h.runtime
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox_id.clone(),
        })
        .await
        .expect("remove sandbox");
    h.runtime
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox_id.clone(),
        })
        .await
        .expect("remove sandbox again");

    let containers = h
        .runtime
        .list_containers(ListContainersRequest { filter: None })
        .await
        .expect("list after sandbox remove")
        .into_inner();
    assert!(containers.containers.iter().all(|c| c.id != a && c.id != b));
}
