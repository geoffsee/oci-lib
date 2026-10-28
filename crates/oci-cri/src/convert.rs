// SPDX-License-Identifier: Apache-2.0

//! CRI → OCI runtime-spec translation.
//!
//! Pure functions over the generated CRI types and the engine's image spec,
//! so they are unit-tested without an engine. The service layer supplies the
//! sandbox namespace paths (from the infra container's PID) and the rootfs.

use std::collections::{BTreeMap, BTreeSet};

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
    let security = config
        .linux
        .as_ref()
        .and_then(|linux| linux.security_context.as_ref());
    validate_user_namespace(security.and_then(|s| s.namespace_options.as_ref()))?;
    #[allow(deprecated)]
    let annotations = security_annotations(
        &config.annotations,
        security.and_then(|s| s.seccomp.as_ref()),
        security
            .map(|s| s.seccomp_profile_path.as_str())
            .unwrap_or_default(),
        false,
    )?;
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
    let options = security.and_then(|s| s.namespace_options.as_ref());
    if !options.is_some_and(|ns| ns.ipc == NamespaceMode::Node as i32) {
        namespaces.push(json!({"type": "ipc"}));
    }
    if !options.is_some_and(|ns| ns.pid == NamespaceMode::Node as i32) {
        namespaces.push(json!({"type": "pid"}));
    }
    namespaces.push(json!({"type": "uts"}));
    let args = image_args(image, &[], &[]);
    let mut spec = json!({
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
        "annotations": annotations,
    });
    spec["process"]["apparmorProfile"] = json!(apparmor_reference(
        security.and_then(|s| s.apparmor.as_ref()),
        ""
    )?);
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
    validate_user_namespace(security.and_then(|s| s.namespace_options.as_ref()))?;
    #[allow(deprecated)]
    let annotations = security_annotations(
        &config.annotations,
        security.and_then(|s| s.seccomp.as_ref()),
        security
            .map(|s| s.seccomp_profile_path.as_str())
            .unwrap_or_default(),
        security.is_some_and(|s| s.privileged),
    )?;
    let args = image_args(image, &config.command, &config.args);
    if args.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "no command: container config and image both leave entrypoint/cmd empty",
            "",
        ));
    }
    let _ = user_selection(config, image)?;
    let (uid, gid, extra_groups) = resolve_user(config, image);
    let mut mounts = default_mounts();
    for mount in &config.mounts {
        if mount.recursive_read_only
            && (!mount.readonly
                || mount.propagation != crate::api::MountPropagation::PropagationPrivate as i32)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "recursive read-only mounts require readonly and private propagation",
                "",
            ));
        }
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
    let capabilities = capabilities_json(security.and_then(|s| s.capabilities.as_ref()))?;
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
    let mut spec = json!({
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
            "rootfsPropagation": if config.mounts.iter().any(|m| m.propagation == crate::api::MountPropagation::PropagationBidirectional as i32) { "rshared" } else { "rslave" },
            "resources": resources,
            "devices": devices,
            "maskedPaths": security.map(|s| s.masked_paths.clone()).unwrap_or_default(),
            "readonlyPaths": security.map(|s| s.readonly_paths.clone()).unwrap_or_default(),
            "sysctl": BTreeMap::<String, String>::new(),
        },
        "annotations": annotations,
    });
    // A joined UTS namespace already has the sandbox's hostname. Setting it
    // again can overwrite an explicit CRI hostname or exceed the kernel limit.
    if namespaces.uts.is_some() {
        spec.as_object_mut().unwrap().remove("hostname");
    }
    #[allow(deprecated)]
    if !security.is_some_and(|s| s.privileged) {
        spec["process"]["apparmorProfile"] = json!(apparmor_reference(
            security.and_then(|s| s.apparmor.as_ref()),
            security
                .map(|s| s.apparmor_profile.as_str())
                .unwrap_or_default()
        )?);
    }
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
        if kind == "pid" && node_mode == NamespaceMode::Container as i32 {
            out.push(json!({"type": kind}));
            return;
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
            .map(|user| user.mode)
            .unwrap_or(NamespaceMode::Node as i32),
    );
    out
}

fn bind_mount(mount: &crate::api::Mount) -> Value {
    let mut options = vec!["rbind".to_string()];
    if mount.recursive_read_only {
        options.push("rro".into());
    }
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
    let mut value = json!({
        "destination": mount.container_path,
        "source": mount.host_path,
        "type": "bind",
        "options": options,
    });
    // Empty arrays are not equivalent to absent mappings in libcontainer:
    // they request an id-mapped mount without any valid ID ranges.
    for (key, mappings) in [
        ("uidMappings", &mount.uid_mappings),
        ("gidMappings", &mount.gid_mappings),
    ] {
        if !mappings.is_empty() {
            value[key] = json!(mappings.iter().map(|m| json!({"containerID": m.container_id, "hostID": m.host_id, "size": m.length})).collect::<Vec<_>>());
        }
    }
    value
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

// Match containers-common's unprivileged default set. Explicit additions also
// enter the inheritable set, as required by the CRI Capability contract.
const DEFAULT_CAPABILITIES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_NET_BIND_SERVICE",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_CHROOT",
];
const ALL_CAPABILITIES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

fn capability_set(names: &[String]) -> Result<BTreeSet<String>> {
    let mut set = BTreeSet::new();
    for name in names {
        let name = name.to_ascii_uppercase();
        let name = name.strip_prefix("CAP_").unwrap_or(&name);
        if name == "ALL" {
            set.extend(ALL_CAPABILITIES.iter().map(|cap| (*cap).to_string()));
        } else {
            let cap = format!("CAP_{name}");
            if !ALL_CAPABILITIES.contains(&cap.as_str()) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("unknown capability {name}"),
                    "",
                ));
            }
            set.insert(cap);
        }
    }
    Ok(set)
}

fn capabilities_json(caps: Option<&crate::api::Capability>) -> Result<Value> {
    let mut base: BTreeSet<String> = DEFAULT_CAPABILITIES
        .iter()
        .map(|cap| (*cap).to_string())
        .collect();
    let mut added = BTreeSet::new();
    let mut ambient = BTreeSet::new();
    if let Some(caps) = caps {
        for cap in capability_set(&caps.drop_capabilities)? {
            base.remove(&cap);
        }
        added = capability_set(&caps.add_capabilities)?;
        ambient = capability_set(&caps.add_ambient_capabilities)?;
        added.extend(ambient.iter().cloned());
        base.extend(added.iter().cloned());
    }
    Ok(
        json!({"bounding": base, "effective": base, "permitted": base,
        "inheritable": added, "ambient": ambient}),
    )
}

fn image_args(image: Option<&ImageSpec>, command: &[String], args: &[String]) -> Vec<String> {
    if !command.is_empty() {
        let mut out = command.to_vec();
        out.extend(args.iter().cloned());
        return out;
    }
    match image {
        Some(image) => {
            let mut out = image.entrypoint.clone();
            out.extend(
                if args.is_empty() { &image.cmd } else { args }
                    .iter()
                    .cloned(),
            );
            out
        }
        None => args.to_vec(),
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

/// Resolve the requested identity before consulting the image's passwd/group files.
pub(crate) fn user_selection(
    config: &ContainerConfig,
    image: Option<&ImageSpec>,
) -> Result<(String, bool)> {
    let security = config
        .linux
        .as_ref()
        .and_then(|l| l.security_context.as_ref());
    if let Some(s) = security {
        let valid_id = |n: i64| (0..=u32::MAX as i64).contains(&n);
        if s.run_as_user.as_ref().is_some_and(|u| !valid_id(u.value))
            || s.run_as_group.as_ref().is_some_and(|g| !valid_id(g.value))
            || s.supplemental_groups.iter().any(|g| !valid_id(*g))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "user and group IDs must fit u32",
                "",
            ));
        }
        if s.run_as_group.is_some() && s.run_as_user.is_none() && s.run_as_username.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "runAsGroup requires runAsUser or runAsUsername",
                "",
            ));
        }
        if s.supplemental_groups_policy != 0 && s.supplemental_groups_policy != 1 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "unknown supplemental groups policy",
                "",
            ));
        }
    }
    let name = security
        .map(|s| s.run_as_username.as_str())
        .unwrap_or_default();
    let mut selected = if let Some(uid) = security.and_then(|s| s.run_as_user.as_ref()) {
        uid.value.to_string()
    } else if !name.is_empty() {
        name.to_owned()
    } else {
        image.map(|i| i.user.clone()).unwrap_or_default()
    };
    if let Some(gid) = security.and_then(|s| s.run_as_group.as_ref()) {
        selected = format!(
            "{}:{}",
            selected.split(':').next().unwrap_or_default(),
            gid.value
        );
    }
    Ok((
        selected,
        security.is_some_and(|s| s.supplemental_groups_policy == 1),
    ))
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
    fn container_pid_mode_creates_a_new_namespace_instead_of_joining_the_sandbox() {
        let paths = NamespacePaths {
            pid: Some("/proc/123/ns/pid".into()),
            ..Default::default()
        };
        let security = LinuxContainerSecurityContext {
            namespace_options: Some(crate::api::NamespaceOption {
                pid: NamespaceMode::Container as i32,
                ..Default::default()
            }),
            ..Default::default()
        };
        let list = namespace_list(&paths, Some(&security));
        let pid = list.iter().find(|n| n["type"] == "pid").unwrap();
        assert!(pid.get("path").is_none());
    }

    #[test]
    fn joined_uts_preserves_the_sandbox_hostname() {
        let paths = NamespacePaths {
            uts: Some("/proc/123/ns/uts".into()),
            ..Default::default()
        };
        let spec: Value = serde_json::from_str(
            &container_spec(
                &config(),
                "/rootfs",
                Some(&image()),
                &paths,
                &"a".repeat(68),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(spec.get("hostname").is_none());
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
    fn args_only_preserves_coredns_image_entrypoint() {
        let image = ImageSpec {
            entrypoint: vec!["/coredns".into()],
            cmd: vec!["-conf".into(), "/etc/coredns/Corefile".into()],
            ..ImageSpec::default()
        };
        let config = ContainerConfig {
            args: vec!["-version".into()],
            ..config()
        };
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
        assert_eq!(spec["process"]["args"], json!(["/coredns", "-version"]));
    }

    #[test]
    fn command_argument_override_matrix() {
        for (command, args, expected) in [
            (vec![], vec![], vec!["/entry", "serve"]),
            (vec![], vec!["--help"], vec!["/entry", "--help"]),
            (vec!["/other"], vec![], vec!["/other"]),
            (vec!["/other"], vec!["arg"], vec!["/other", "arg"]),
        ] {
            let strings =
                |items: Vec<&str>| items.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(
                image_args(Some(&image()), &strings(command), &strings(args)),
                strings(expected)
            );
        }
    }

    #[test]
    fn capabilities_default_drop_all_add_and_ambient() {
        use crate::api::Capability;
        let spec_for = |caps| {
            let mut config = config();
            config.linux = Some(LinuxContainerConfig {
                security_context: Some(LinuxContainerSecurityContext {
                    capabilities: caps,
                    ..Default::default()
                }),
                ..Default::default()
            });
            serde_json::from_str::<Value>(
                &container_spec(
                    &config,
                    "/rootfs",
                    Some(&image()),
                    &NamespacePaths::default(),
                    "pod",
                )
                .unwrap(),
            )
            .unwrap()
        };
        for caps in [None, Some(Capability::default())] {
            let spec = spec_for(caps);
            for set in ["bounding", "effective", "permitted"] {
                assert!(
                    spec["process"]["capabilities"][set]
                        .as_array()
                        .unwrap()
                        .contains(&json!("CAP_NET_BIND_SERVICE"))
                );
                assert!(
                    !spec["process"]["capabilities"][set]
                        .as_array()
                        .unwrap()
                        .contains(&json!("CAP_SYS_ADMIN"))
                );
            }
            assert_eq!(spec["process"]["capabilities"]["ambient"], json!([]));
            assert_eq!(spec["process"]["capabilities"]["inheritable"], json!([]));
        }
        let spec = spec_for(Some(Capability {
            drop_capabilities: vec!["ALL".into()],
            add_capabilities: vec!["NET_BIND_SERVICE".into(), "CAP_NET_BIND_SERVICE".into()],
            ..Default::default()
        }));
        for set in ["bounding", "effective", "permitted", "inheritable"] {
            assert_eq!(
                spec["process"]["capabilities"][set],
                json!(["CAP_NET_BIND_SERVICE"])
            );
        }
        assert_eq!(spec["process"]["capabilities"]["ambient"], json!([]));
        let spec = spec_for(Some(Capability {
            drop_capabilities: vec!["NET_BIND_SERVICE".into()],
            add_ambient_capabilities: vec!["SYS_CHROOT".into()],
            ..Default::default()
        }));
        assert!(
            !spec["process"]["capabilities"]["bounding"]
                .as_array()
                .unwrap()
                .contains(&json!("CAP_NET_BIND_SERVICE"))
        );
        assert_eq!(
            spec["process"]["capabilities"]["ambient"],
            json!(["CAP_SYS_CHROOT"])
        );
        assert_eq!(
            spec["process"]["capabilities"]["inheritable"],
            json!(["CAP_SYS_CHROOT"])
        );
        let spec = spec_for(Some(Capability {
            drop_capabilities: vec!["ALL".into()],
            ..Default::default()
        }));
        assert_eq!(spec["process"]["capabilities"]["bounding"], json!([]));
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

#[cfg(test)]
mod mount_mapping_regressions {
    use super::*;
    use crate::api::{IdMapping, Mount};

    #[test]
    fn ordinary_bind_mounts_do_not_request_id_mapping() {
        let value = bind_mount(&Mount {
            host_path: "/host/token".into(),
            container_path: "/var/run/secrets/token".into(),
            readonly: true,
            ..Default::default()
        });
        assert!(value.get("uidMappings").is_none());
        assert!(value.get("gidMappings").is_none());
        assert_eq!(value["options"], json!(["rbind", "ro", "rprivate"]));
    }

    #[test]
    fn explicit_mount_mappings_are_preserved() {
        let mapping = IdMapping {
            container_id: 0,
            host_id: 100000,
            length: 65536,
        };
        let value = bind_mount(&Mount {
            uid_mappings: vec![mapping],
            gid_mappings: vec![mapping],
            ..Default::default()
        });
        assert_eq!(
            value["uidMappings"],
            json!([{"containerID":0,"hostID":100000,"size":65536}])
        );
        assert_eq!(value["gidMappings"], value["uidMappings"]);
    }
}

const SECCOMP_ANNOTATION: &str = "io.oci-cri.seccomp";
const PRIVILEGED_ANNOTATION: &str = "io.oci-cri.privileged";

fn security_annotations(
    source: &std::collections::HashMap<String, String>,
    profile: Option<&crate::api::SecurityProfile>,
    legacy: &str,
    privileged: bool,
) -> Result<std::collections::HashMap<String, String>> {
    let mut annotations = source.clone();
    // CRI annotations must not impersonate runtime-owned security settings.
    annotations.remove(SECCOMP_ANNOTATION);
    annotations.remove(PRIVILEGED_ANNOTATION);
    if privileged {
        annotations.insert(PRIVILEGED_ANNOTATION.into(), "true".into());
        return Ok(annotations);
    }
    if let Some(reference) = seccomp_reference(profile, legacy)? {
        annotations.insert(SECCOMP_ANNOTATION.into(), reference);
    }
    Ok(annotations)
}

fn seccomp_reference(
    profile: Option<&crate::api::SecurityProfile>,
    legacy: &str,
) -> Result<Option<String>> {
    use crate::api::security_profile::ProfileType;
    let path = if let Some(profile) = profile {
        let kind = ProfileType::try_from(profile.profile_type).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "unknown seccomp profile type",
                "",
            )
        })?;
        if kind != ProfileType::Localhost && !profile.localhost_ref.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "localhost_ref requires a Localhost seccomp profile",
                "",
            ));
        }
        match kind {
            ProfileType::Unconfined => return Ok(None),
            ProfileType::RuntimeDefault => return Ok(Some("runtime/default".into())),
            ProfileType::Localhost => profile.localhost_ref.as_str(),
        }
    } else {
        match legacy {
            "" | "unconfined" => return Ok(None),
            "runtime/default" | "docker/default" => return Ok(Some("runtime/default".into())),
            value => value.strip_prefix("localhost/").unwrap_or(""),
        }
    };
    if !std::path::Path::new(path).is_absolute() || path.contains('\0') {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Localhost seccomp requires an absolute profile path",
            "",
        ));
    }
    Ok(Some(path.into()))
}

fn apparmor_reference(
    profile: Option<&crate::api::SecurityProfile>,
    legacy: &str,
) -> Result<String> {
    use crate::api::security_profile::ProfileType;
    let name = if let Some(profile) = profile {
        match ProfileType::try_from(profile.profile_type) {
            Ok(ProfileType::RuntimeDefault) => return Ok("runtime/default".into()),
            Ok(ProfileType::Unconfined) => return Ok("unconfined".into()),
            Ok(ProfileType::Localhost) => profile.localhost_ref.as_str(),
            Err(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "unknown AppArmor profile type",
                    "",
                ));
            }
        }
    } else {
        match legacy {
            "" | "unconfined" => return Ok(legacy.into()),
            "runtime/default" | "docker/default" => return Ok("runtime/default".into()),
            name => name.strip_prefix("localhost/").unwrap_or(""),
        }
    };
    if name.is_empty() || name.contains(['\0', '\n']) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "invalid AppArmor profile name",
            "",
        ));
    }
    Ok(name.into())
}

fn validate_user_namespace(options: Option<&crate::api::NamespaceOption>) -> Result<()> {
    let Some(user) = options.and_then(|ns| ns.userns_options.as_ref()) else {
        return Ok(());
    };
    match NamespaceMode::try_from(user.mode) {
        Ok(NamespaceMode::Node) if user.uids.is_empty() && user.gids.is_empty() => Ok(()),
        Ok(NamespaceMode::Pod) => Err(Error::new(
            ErrorCode::Unsupported,
            "user namespace mappings are not implemented",
            "requested isolation was not applied",
        )),
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            "invalid user namespace mode or mappings",
            "",
        )),
    }
}

#[cfg(test)]
mod seccomp_regressions {
    use super::*;
    use crate::api::{SecurityProfile, security_profile::ProfileType};

    #[test]
    fn seccomp_profiles_are_translated_and_validated() {
        assert_eq!(
            seccomp_reference(Some(&SecurityProfile::default()), "")
                .unwrap()
                .as_deref(),
            Some("runtime/default")
        );
        assert_eq!(
            seccomp_reference(None, "runtime/default")
                .unwrap()
                .as_deref(),
            Some("runtime/default")
        );
        assert_eq!(
            seccomp_reference(None, "localhost//tmp/profile.json")
                .unwrap()
                .as_deref(),
            Some("/tmp/profile.json")
        );
        let mut profile = SecurityProfile {
            profile_type: ProfileType::Localhost as i32,
            localhost_ref: "relative.json".into(),
        };
        assert!(seccomp_reference(Some(&profile), "").is_err());
        profile.localhost_ref = "/tmp/profile.json".into();
        assert_eq!(
            seccomp_reference(Some(&profile), "").unwrap().as_deref(),
            Some("/tmp/profile.json")
        );
        profile.profile_type = ProfileType::Unconfined as i32;
        profile.localhost_ref.clear();
        assert!(
            seccomp_reference(Some(&profile), "runtime/default")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn caller_annotations_cannot_override_security_context() {
        let input = std::collections::HashMap::from([
            (PRIVILEGED_ANNOTATION.into(), "true".into()),
            (SECCOMP_ANNOTATION.into(), "runtime/default".into()),
        ]);
        assert!(
            security_annotations(&input, None, "", false)
                .unwrap()
                .is_empty()
        );
        let result = security_annotations(&input, None, "localhost/missing", true).unwrap();
        assert_eq!(result.get(PRIVILEGED_ANNOTATION).unwrap(), "true");
        assert!(!result.contains_key(SECCOMP_ANNOTATION));
    }

    #[test]
    fn unsupported_user_namespaces_are_not_silently_ignored() {
        let mut ns = crate::api::NamespaceOption {
            userns_options: Some(crate::api::UserNamespace::default()),
            ..Default::default()
        };
        assert_eq!(
            validate_user_namespace(Some(&ns)).unwrap_err().code(),
            ErrorCode::Unsupported
        );
        ns.userns_options.as_mut().unwrap().mode = NamespaceMode::Node as i32;
        assert!(validate_user_namespace(Some(&ns)).is_ok());
        ns.userns_options.as_mut().unwrap().mode = NamespaceMode::Container as i32;
        assert_eq!(
            validate_user_namespace(Some(&ns)).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }
}

#[cfg(test)]
mod conformance_validation_regressions {
    use super::*;
    use crate::api::*;

    fn config() -> ContainerConfig {
        ContainerConfig {
            image: Some(crate::api::ImageSpec::default()),
            command: vec!["/bin/true".into()],
            ..Default::default()
        }
    }

    #[test]
    fn recursive_readonly_requires_private_readonly_mounts() {
        let mut config = config();
        for (readonly, propagation) in [(false, 0), (true, 1), (true, 2)] {
            config.mounts = vec![Mount {
                recursive_read_only: true,
                readonly,
                propagation,
                ..Default::default()
            }];
            assert_eq!(
                container_spec(&config, "/rootfs", None, &NamespacePaths::default(), "pod")
                    .unwrap_err()
                    .code(),
                ErrorCode::InvalidArgument
            );
        }
        config.mounts[0].propagation = 0;
        let spec: Value = serde_json::from_str(
            &container_spec(&config, "/rootfs", None, &NamespacePaths::default(), "pod").unwrap(),
        )
        .unwrap();
        assert!(
            spec["mounts"].as_array().unwrap().last().unwrap()["options"]
                .as_array()
                .unwrap()
                .contains(&json!("rro"))
        );
    }

    #[test]
    fn user_selection_rejects_invalid_ids_and_group_without_user() {
        let mut config = config();
        config.linux = Some(LinuxContainerConfig {
            security_context: Some(LinuxContainerSecurityContext {
                run_as_group: Some(Int64Value { value: 42 }),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert!(user_selection(&config, None).is_err());
        let security = config
            .linux
            .as_mut()
            .unwrap()
            .security_context
            .as_mut()
            .unwrap();
        security.run_as_user = Some(Int64Value { value: -1 });
        assert!(user_selection(&config, None).is_err());
        config
            .linux
            .as_mut()
            .unwrap()
            .security_context
            .as_mut()
            .unwrap()
            .run_as_user = Some(Int64Value { value: 1000 });
        assert_eq!(
            user_selection(&config, None).unwrap(),
            ("1000:42".into(), false)
        );
    }

    #[test]
    fn sandbox_host_ipc_and_pid_are_honored() {
        let config = PodSandboxConfig {
            linux: Some(LinuxPodSandboxConfig {
                security_context: Some(LinuxSandboxSecurityContext {
                    namespace_options: Some(NamespaceOption {
                        ipc: NamespaceMode::Node as i32,
                        pid: NamespaceMode::Node as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let spec: Value =
            serde_json::from_str(&sandbox_spec(&config, "/rootfs", None, "pod").unwrap()).unwrap();
        assert!(
            !spec["linux"]["namespaces"]
                .as_array()
                .unwrap()
                .iter()
                .any(|ns| ns["type"] == "ipc" || ns["type"] == "pid")
        );
        let spec: Value = serde_json::from_str(
            &sandbox_spec(&PodSandboxConfig::default(), "/rootfs", None, "pod").unwrap(),
        )
        .unwrap();
        assert!(
            spec["linux"]["namespaces"]
                .as_array()
                .unwrap()
                .iter()
                .any(|ns| ns["type"] == "pid")
        );
    }
}
