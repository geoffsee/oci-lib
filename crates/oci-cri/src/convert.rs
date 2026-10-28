// SPDX-License-Identifier: Apache-2.0

//! CRI → OCI runtime-spec translation.
//!
//! Pure functions over the generated CRI types and the engine's image spec,
//! so they are unit-tested without an engine. The service layer supplies the
//! sandbox namespace paths (from the infra container's PID) and the rootfs.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::api::{ContainerConfig, LinuxContainerResources, NamespaceMode, PodSandboxConfig};
use crate::engine::ImageSpec;
use crate::error::{Error, ErrorCode, Result};

/// Paths of the sandbox namespaces a container may join
/// (`/proc/<infra-pid>/ns/<type>`). `None` means "create/host default".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespacePaths {
    /// Network namespace path.
    pub network: Option<String>,
    /// IPC namespace path.
    pub ipc: Option<String>,
    /// UTS namespace path.
    pub uts: Option<String>,
    /// PID namespace path.
    pub pid: Option<String>,
    /// User namespace path.
    pub user: Option<String>,
}

/// The spec for a pod sandbox infra (pause) container.
pub fn sandbox_spec(
    config: &PodSandboxConfig,
    rootfs: &str,
    image: Option<&ImageSpec>,
    hostname: &str,
) -> Result<String> {
    let host_network = config
        .linux
        .as_ref()
        .and_then(|l| l.security_context.as_ref())
        .and_then(|s| s.namespace_options.as_ref())
        .map(|ns| ns.network == NamespaceMode::Node as i32)
        .unwrap_or(false);
    let mut namespaces = vec![json!({"type": "mount"})];
    if !host_network {
        namespaces.push(json!({"type": "network"}));
    }
    namespaces.push(json!({"type": "ipc"}));
    namespaces.push(json!({"type": "uts"}));
    let args = image_args(image, &[], &[]);
    let spec = json!({
        "ociVersion": "1.0.2-dev",
        "hostname": hostname,
        "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": if args.is_empty() { vec!["/pause".to_string()] } else { args },
            "env": image_env(image, &[]),
            "cwd": "/",
            "noNewPrivileges": false,
        },
        "root": {"path": rootfs, "readonly": false},
        "mounts": default_mounts(),
        "linux": {
            "namespaces": namespaces,
            "sysctl": config.linux.as_ref().map(|l| l.sysctls.clone()).unwrap_or_default(),
        },
        "annotations": config.annotations,
    });
    to_string(spec)
}

/// The spec for one workload container in a sandbox.
pub fn container_spec(
    config: &ContainerConfig,
    rootfs: &str,
    image: Option<&ImageSpec>,
    namespaces: &NamespacePaths,
    hostname: &str,
) -> Result<String> {
    if config.image.is_none() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "container config has no image",
            "",
        ));
    }
    let linux = config.linux.as_ref();
    let security = linux.and_then(|l| l.security_context.as_ref());
    let args = image_args(image, &config.command, &config.args);
    if args.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "no command: container config and image both leave entrypoint/cmd empty",
            "",
        ));
    }
    let (uid, gid, extra_groups) = resolve_user(config, image);
    let mut mounts = default_mounts();
    for mount in &config.mounts {
        mounts.push(bind_mount(mount));
    }
    if let Some(image) = image {
        for volume in image.volumes.keys() {
            mounts.push(json!({
                "destination": volume,
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev", "noexec"],
            }));
        }
    }
    let mut devices = Vec::new();
    for device in &config.devices {
        devices.push(json!({
            "path": device.container_path,
            "type": "c",
            "major": 0,
            "minor": 0,
            "uid": uid,
            "gid": gid,
        }));
        // Host device nodes are bind-mounted too; the shim resolves the
        // major/minor from the host path when it creates the container.
        mounts.push(json!({
            "destination": device.container_path,
            "source": device.host_path,
            "type": "bind",
            "options": ["bind", "rprivate"],
        }));
    }
    let capabilities = security
        .and_then(|s| s.capabilities.as_ref())
        .map(|caps| {
            json!({
                "bounding": caps.add_capabilities,
                "effective": caps.add_capabilities,
                "permitted": caps.add_capabilities,
                "ambient": [],
                "inheritable": [],
            })
        })
        .unwrap_or_else(|| json!({}));
    let namespace_json = namespace_list(namespaces, security);
    let resources = linux
        .and_then(|l| l.resources.as_ref())
        .map(resources_json)
        .unwrap_or_else(|| json!({}));
    let cwd = if !config.working_dir.is_empty() {
        config.working_dir.clone()
    } else if let Some(image) = image {
        if image.working_dir.is_empty() {
            "/".to_string()
        } else {
            image.working_dir.clone()
        }
    } else {
        "/".to_string()
    };
    let spec = json!({
        "ociVersion": "1.0.2-dev",
        "hostname": hostname,
        "process": {
            "terminal": config.tty,
            "user": {"uid": uid, "gid": gid, "additionalGids": extra_groups},
            "args": args,
            "env": image_env(image, &config.envs.iter().map(|kv| format!("{}={}", kv.key, String::from_utf8_lossy(&kv.value))).collect::<Vec<_>>()),
            "cwd": cwd,
            "capabilities": capabilities,
            "noNewPrivileges": security.map(|s| s.no_new_privs).unwrap_or(false),
            "rlimits": [{"type": "RLIMIT_NOFILE", "soft": 1048576u64, "hard": 1048576u64}],
        },
        "root": {
            "path": rootfs,
            "readonly": security.map(|s| s.readonly_rootfs).unwrap_or(false),
        },
        "mounts": mounts,
        "linux": {
            "namespaces": namespace_json,
            "resources": resources,
            "devices": devices,
            "maskedPaths": security.map(|s| s.masked_paths.clone()).unwrap_or_default(),
            "readonlyPaths": security.map(|s| s.readonly_paths.clone()).unwrap_or_default(),
            "sysctl": BTreeMap::<String, String>::new(),
        },
        "annotations": config.annotations,
    });
    to_string(spec)
}

/// OCI `linux.resources` JSON for a CRI resource block (also used alone by
/// `UpdateContainerResources`).
pub fn resources_json(resources: &LinuxContainerResources) -> Value {
    let mut out = serde_json::Map::new();
    if resources.cpu_shares != 0 || resources.cpu_period != 0 || resources.cpu_quota != 0 {
        out.insert(
            "cpu".into(),
            json!({
                "shares": resources.cpu_shares,
                "period": resources.cpu_period,
                "quota": resources.cpu_quota,
                "cpus": resources.cpuset_cpus,
                "mems": resources.cpuset_mems,
            }),
        );
    }
    if resources.memory_limit_in_bytes != 0 || resources.memory_swap_limit_in_bytes != 0 {
        out.insert(
            "memory".into(),
            json!({
                "limit": resources.memory_limit_in_bytes,
                "swap": resources.memory_swap_limit_in_bytes,
            }),
        );
    }
    if !resources.hugepage_limits.is_empty() {
        out.insert(
            "hugepageLimits".into(),
            Value::Array(
                resources
                    .hugepage_limits
                    .iter()
                    .map(|h| json!({"pageSize": h.page_size, "limit": h.limit}))
                    .collect(),
            ),
        );
    }
    if !resources.unified.is_empty() {
        out.insert("unified".into(), json!(resources.unified));
    }
    Value::Object(out)
}

fn namespace_list(
    paths: &NamespacePaths,
    security: Option<&crate::api::LinuxContainerSecurityContext>,
) -> Vec<Value> {
    let options = security.and_then(|s| s.namespace_options.as_ref());
    let mode = |get: fn(&crate::api::NamespaceOption) -> i32| -> i32 {
        options.map(get).unwrap_or(NamespaceMode::Pod as i32)
    };
    let mut out = vec![json!({"type": "mount"}), json!({"type": "cgroup"})];
    let mut push = |kind: &str, path: &Option<String>, node_mode: i32| {
        if node_mode == NamespaceMode::Node as i32 {
            return; // host namespace: omit entirely
        }
        match path {
            Some(path) => out.push(json!({"type": kind, "path": path})),
            None => out.push(json!({"type": kind})),
        }
    };
    push("network", &paths.network, mode(|ns| ns.network));
    push("ipc", &paths.ipc, mode(|ns| ns.ipc));
    push("uts", &paths.uts, NamespaceMode::Pod as i32);
    push("pid", &paths.pid, mode(|ns| ns.pid));
    push(
        "user",
        &paths.user,
        options
            .and_then(|ns| ns.userns_options.as_ref())
            .map(|_| NamespaceMode::Pod as i32)
            .unwrap_or(NamespaceMode::Node as i32),
    );
    out
}

fn bind_mount(mount: &crate::api::Mount) -> Value {
    let mut options = vec!["bind".to_string()];
    options.push(if mount.readonly {
        "ro".to_string()
    } else {
        "rw".to_string()
    });
    options.push(
        match crate::api::MountPropagation::try_from(mount.propagation) {
            Ok(crate::api::MountPropagation::PropagationPrivate) | Err(_) => "rprivate".to_string(),
            Ok(crate::api::MountPropagation::PropagationHostToContainer) => "rslave".to_string(),
            Ok(crate::api::MountPropagation::PropagationBidirectional) => "rshared".to_string(),
        },
    );
    json!({
        "destination": mount.container_path,
        "source": mount.host_path,
        "type": "bind",
        "options": options,
        "uidMappings": mount.uid_mappings.iter().map(|m| json!({"containerID": m.container_id, "hostID": m.host_id, "size": m.length})).collect::<Vec<_>>(),
        "gidMappings": mount.gid_mappings.iter().map(|m| json!({"containerID": m.container_id, "hostID": m.host_id, "size": m.length})).collect::<Vec<_>>(),
    })
}

fn default_mounts() -> Vec<Value> {
    vec![
        json!({"destination": "/proc", "type": "proc", "source": "proc"}),
        json!({"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}),
        json!({"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]}),
        json!({"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]}),
        json!({"destination": "/dev/mqueue", "type": "mqueue", "source": "mqueue", "options": ["nosuid", "noexec", "nodev"]}),
        json!({"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev"]}),
        json!({"destination": "/etc/resolv.conf", "type": "bind", "source": "/etc/resolv.conf", "options": ["bind", "ro", "rprivate"]}),
    ]
}

fn image_args(image: Option<&ImageSpec>, command: &[String], args: &[String]) -> Vec<String> {
    if !command.is_empty() || !args.is_empty() {
        let mut out = command.to_vec();
        out.extend(args.iter().cloned());
        return out;
    }
    match image {
        Some(image) => {
            let mut out = image.entrypoint.clone();
            out.extend(image.cmd.iter().cloned());
            out
        }
        None => Vec::new(),
    }
}

fn image_env(image: Option<&ImageSpec>, extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = image.map(|i| i.env.clone()).unwrap_or_default();
    if !out.iter().any(|e| e.starts_with("PATH=")) {
        out.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
    }
    for entry in extra {
        let key = entry.split('=').next().unwrap_or("");
        out.retain(|e| e.split('=').next().unwrap_or("") != key);
        out.push(entry.clone());
    }
    out
}

fn resolve_user(config: &ContainerConfig, image: Option<&ImageSpec>) -> (u32, u32, Vec<u32>) {
    let security = config
        .linux
        .as_ref()
        .and_then(|l| l.security_context.as_ref());
    let mut groups: Vec<u32> = security
        .map(|s| s.supplemental_groups.iter().map(|g| *g as u32).collect())
        .unwrap_or_default();
    if let Some(user) = security.and_then(|s| s.run_as_user.as_ref()) {
        return (
            user.value as u32,
            security
                .and_then(|s| s.run_as_group.as_ref())
                .map(|g| g.value as u32)
                .unwrap_or(0),
            std::mem::take(&mut groups),
        );
    }
    let username = security.map(|s| s.run_as_username.as_str()).unwrap_or("");
    if !username.is_empty() {
        return parse_user(username);
    }
    match image {
        Some(image) if !image.user.is_empty() => parse_user(&image.user),
        _ => (0, 0, groups),
    }
}

/// Parse `user`, `uid`, `uid:gid`, or `user:group` (numeric only; name lookup
/// against the rootfs is the caller's refinement and falls back to root).
pub fn parse_user(text: &str) -> (u32, u32, Vec<u32>) {
    let mut parts = text.split(':');
    let uid = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    let gid = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    (uid, gid, Vec::new())
}

fn to_string(spec: Value) -> Result<String> {
    serde_json::to_string(&spec).map_err(|err| Error::new(ErrorCode::Internal, err.to_string(), ""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        ContainerMetadata, ImageSpec as CriImageSpec, KeyValue, LinuxContainerConfig,
        LinuxContainerSecurityContext, Mount,
    };

    fn image() -> ImageSpec {
        ImageSpec {
            entrypoint: vec!["/entry".into()],
            cmd: vec!["serve".into()],
            env: vec!["A=1".into()],
            working_dir: "/app".into(),
            ..ImageSpec::default()
        }
    }

    fn config() -> ContainerConfig {
        ContainerConfig {
            metadata: Some(ContainerMetadata {
                name: "web".into(),
                attempt: 1,
            }),
            image: Some(CriImageSpec {
                image: "example/web:latest".into(),
                ..CriImageSpec::default()
            }),
            ..ContainerConfig::default()
        }
    }

    #[test]
    fn falls_back_to_image_entrypoint_and_cmd() {
        let spec: Value = serde_json::from_str(
            &container_spec(
                &config(),
                "/rootfs",
                Some(&image()),
                &NamespacePaths::default(),
                "pod",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(spec["process"]["args"], json!(["/entry", "serve"]));
        assert_eq!(spec["process"]["cwd"], json!("/app"));
        assert!(
            spec["process"]["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e == "A=1")
        );
    }

    #[test]
    fn explicit_command_overrides_image_and_mounts_bind() {
        let mut config = config();
        config.command = vec!["/bin/app".into()];
        config.args = vec!["--flag".into()];
        config.mounts = vec![Mount {
            container_path: "/data".into(),
            host_path: "/host/data".into(),
            readonly: true,
            ..Mount::default()
        }];
        config.envs = vec![KeyValue {
            key: "A".into(),
            value: "2".into(),
        }];
        let spec: Value = serde_json::from_str(
            &container_spec(
                &config,
                "/rootfs",
                Some(&image()),
                &NamespacePaths::default(),
                "pod",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(spec["process"]["args"], json!(["/bin/app", "--flag"]));
        let mounts = spec["mounts"].as_array().unwrap();
        let data = mounts.iter().find(|m| m["destination"] == "/data").unwrap();
        assert!(
            data["options"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o == "ro")
        );
        assert!(
            spec["process"]["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e == "A=2")
        );
    }

    #[test]
    fn rejects_a_container_with_no_command_anywhere() {
        let mut config = config();
        config.command = Vec::new();
        let err = container_spec(&config, "/rootfs", None, &NamespacePaths::default(), "pod")
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn security_context_sets_user_and_readonly_root() {
        let mut config = config();
        config.linux = Some(LinuxContainerConfig {
            security_context: Some(LinuxContainerSecurityContext {
                run_as_user: Some(crate::api::Int64Value { value: 1000 }),
                run_as_group: Some(crate::api::Int64Value { value: 1001 }),
                readonly_rootfs: true,
                supplemental_groups: vec![27],
                ..LinuxContainerSecurityContext::default()
            }),
            ..LinuxContainerConfig::default()
        });
        let spec: Value = serde_json::from_str(
            &container_spec(
                &config,
                "/rootfs",
                Some(&image()),
                &NamespacePaths::default(),
                "pod",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(spec["process"]["user"]["uid"], json!(1000));
        assert_eq!(spec["process"]["user"]["gid"], json!(1001));
        assert_eq!(spec["root"]["readonly"], json!(true));
        assert_eq!(spec["process"]["user"]["additionalGids"], json!([27]));
    }

    #[test]
    fn rejects_a_container_with_no_image() {
        let mut config = config();
        config.image = None;
        let err = container_spec(
            &config,
            "/rootfs",
            Some(&image()),
            &NamespacePaths::default(),
            "pod",
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn parse_user_accepts_uid_gid_and_non_numeric() {
        assert_eq!(parse_user("1000:1001"), (1000, 1001, vec![]));
        assert_eq!(parse_user("42"), (42, 0, vec![]));
        assert_eq!(parse_user("nobody"), (0, 0, vec![]));
        assert_eq!(parse_user(""), (0, 0, vec![]));
    }

    #[test]
    fn sandbox_host_network_omits_network_namespace() {
        use crate::api::{
            LinuxPodSandboxConfig, LinuxSandboxSecurityContext, NamespaceOption, PodSandboxMetadata,
        };
        let config = PodSandboxConfig {
            metadata: Some(PodSandboxMetadata {
                name: "hostnet".into(),
                ..PodSandboxMetadata::default()
            }),
            linux: Some(LinuxPodSandboxConfig {
                security_context: Some(LinuxSandboxSecurityContext {
                    namespace_options: Some(NamespaceOption {
                        network: NamespaceMode::Node as i32,
                        ..NamespaceOption::default()
                    }),
                    ..LinuxSandboxSecurityContext::default()
                }),
                ..LinuxPodSandboxConfig::default()
            }),
            ..PodSandboxConfig::default()
        };
        let spec: Value =
            serde_json::from_str(&sandbox_spec(&config, "/rootfs", None, "hostnet").unwrap())
                .unwrap();
        let namespaces = spec["linux"]["namespaces"].as_array().unwrap();
        assert!(namespaces.iter().all(|ns| ns["type"] != "network"));
        assert_eq!(spec["process"]["args"], json!(["/pause"]));
    }

    #[test]
    fn resources_json_emits_cpu_memory_and_hugepages() {
        use crate::api::HugepageLimit;
        use std::collections::HashMap;
        let resources = LinuxContainerResources {
            cpu_shares: 1024,
            cpu_period: 100_000,
            cpu_quota: 50_000,
            cpuset_cpus: "0-1".into(),
            cpuset_mems: "0".into(),
            memory_limit_in_bytes: 256 * 1024 * 1024,
            memory_swap_limit_in_bytes: 512 * 1024 * 1024,
            hugepage_limits: vec![HugepageLimit {
                page_size: "2MB".into(),
                limit: 4,
            }],
            unified: HashMap::from([("memory.min".into(), "1M".into())]),
            ..LinuxContainerResources::default()
        };
        let value = resources_json(&resources);
        assert_eq!(value["cpu"]["shares"], json!(1024));
        assert_eq!(value["cpu"]["cpus"], json!("0-1"));
        assert_eq!(value["memory"]["limit"], json!(256 * 1024 * 1024));
        assert_eq!(value["hugepageLimits"][0]["pageSize"], json!("2MB"));
        assert_eq!(value["unified"]["memory.min"], json!("1M"));
        assert!(
            resources_json(&LinuxContainerResources::default())
                .as_object()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn mount_propagation_and_host_pid_shape_the_spec() {
        use crate::api::{MountPropagation, NamespaceOption};
        let mut config = config();
        config.mounts = vec![Mount {
            container_path: "/shared".into(),
            host_path: "/host/shared".into(),
            readonly: false,
            propagation: MountPropagation::PropagationBidirectional as i32,
            ..Mount::default()
        }];
        config.linux = Some(LinuxContainerConfig {
            security_context: Some(LinuxContainerSecurityContext {
                namespace_options: Some(NamespaceOption {
                    pid: NamespaceMode::Node as i32,
                    network: NamespaceMode::Pod as i32,
                    ..NamespaceOption::default()
                }),
                ..LinuxContainerSecurityContext::default()
            }),
            ..LinuxContainerConfig::default()
        });
        let namespaces = NamespacePaths {
            network: Some("/proc/1/ns/net".into()),
            ..NamespacePaths::default()
        };
        let spec: Value = serde_json::from_str(
            &container_spec(&config, "/rootfs", Some(&image()), &namespaces, "pod").unwrap(),
        )
        .unwrap();
        let mounts = spec["mounts"].as_array().unwrap();
        let shared = mounts
            .iter()
            .find(|m| m["destination"] == "/shared")
            .unwrap();
        assert!(
            shared["options"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o == "rshared")
        );
        let ns = spec["linux"]["namespaces"].as_array().unwrap();
        assert!(
            ns.iter()
                .any(|n| n["type"] == "network" && n["path"] == "/proc/1/ns/net")
        );
        assert!(ns.iter().all(|n| n["type"] != "pid"));
    }

    #[test]
    fn working_dir_override_and_image_volumes() {
        let mut config = config();
        config.working_dir = "/work".into();
        let mut image = image();
        image.volumes.insert("/var/data".into(), String::new());
        let spec: Value = serde_json::from_str(
            &container_spec(
                &config,
                "/rootfs",
                Some(&image),
                &NamespacePaths::default(),
                "pod",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(spec["process"]["cwd"], json!("/work"));
        let mounts = spec["mounts"].as_array().unwrap();
        let volume = mounts
            .iter()
            .find(|m| m["destination"] == "/var/data")
            .unwrap();
        assert_eq!(volume["type"], json!("tmpfs"));
    }
}
