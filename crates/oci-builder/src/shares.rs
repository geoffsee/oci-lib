// SPDX-License-Identifier: Apache-2.0

//! Host directories exported into the Linux guest, and the path rewrite that
//! goes with them. Virtiofs devices are fixed before the VM starts, so every
//! directory a call needs is collected first.

use std::path::{Path, PathBuf};

pub const TAG_CONTEXT: &str = "context";
pub const TAG_ROOT: &str = "root";
pub const TAG_RUNROOT: &str = "runroot";
pub const TAG_POLICY: &str = "policy";
pub const TAG_REGISTRIES: &str = "registries";
pub const TAG_AUTH: &str = "auth";

pub const GUEST_CONTEXT: &str = "/mnt/context";
pub const GUEST_ROOT: &str = "/mnt/root";
pub const GUEST_RUNROOT: &str = "/mnt/runroot";
pub const GUEST_POLICY: &str = "/mnt/policy";
pub const GUEST_REGISTRIES: &str = "/mnt/registries";
pub const GUEST_AUTH: &str = "/mnt/auth";

/// One host directory mounted in the guest at `guest`.
///
/// `read_only` is set for the build-context share only. The storage root
/// stays writable because the guest writes its graph image there. Other
/// shares stay writable too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub tag: &'static str,
    pub host: PathBuf,
    pub guest: &'static str,
    pub read_only: bool,
}

/// Directories the next boot has to export.
///
/// `context` is the build context. The dockerfile has to live inside it.
/// File settings contribute their parent directory. A host path that is
/// already exported is not added again; [`guest_path`] still rewrites it.
pub struct ShareRequest<'a> {
    pub context: Option<&'a Path>,
    pub dockerfile: Option<&'a Path>,
    pub storage_root: Option<&'a Path>,
    pub run_root: Option<&'a Path>,
    pub signature_policy: Option<&'a Path>,
    pub registries_conf: Option<&'a Path>,
    pub auth_file: Option<&'a Path>,
}

pub fn plan_shares(request: ShareRequest<'_>) -> Result<Vec<Export>, String> {
    if let (Some(dockerfile), Some(context)) = (request.dockerfile, request.context) {
        if !dockerfile.starts_with(context) {
            return Err(format!(
                "dockerfile {} is outside the build context {}",
                dockerfile.display(),
                context.display()
            ));
        }
    }
    let mut exports = Vec::new();
    if let Some(context) = request.context {
        add_dir(&mut exports, TAG_CONTEXT, GUEST_CONTEXT, context, true)?;
    }
    if let Some(root) = request.storage_root {
        add_dir(&mut exports, TAG_ROOT, GUEST_ROOT, root, false)?;
    }
    if let Some(run) = request.run_root {
        add_dir(&mut exports, TAG_RUNROOT, GUEST_RUNROOT, run, false)?;
    }
    if let Some(policy) = request.signature_policy {
        add_file_parent(&mut exports, TAG_POLICY, GUEST_POLICY, policy, false)?;
    }
    if let Some(registries) = request.registries_conf {
        add_file_parent(
            &mut exports,
            TAG_REGISTRIES,
            GUEST_REGISTRIES,
            registries,
            false,
        )?;
    }
    if let Some(auth) = request.auth_file {
        add_file_parent(&mut exports, TAG_AUTH, GUEST_AUTH, auth, false)?;
    }
    Ok(exports)
}

/// Rewrite a host path to the guest path under the longest matching export.
pub fn guest_path(path: &Path, exports: &[Export]) -> Result<String, String> {
    let path = canonicalize(path)?;
    let export = exports
        .iter()
        .filter(|export| path.starts_with(&export.host))
        .max_by_key(|export| export.host.as_os_str().len())
        .ok_or_else(|| {
            format!(
                "path {} is not inside a directory exported to the guest",
                path.display()
            )
        })?;
    let relative = path
        .strip_prefix(&export.host)
        .map_err(|err| err.to_string())?;
    let mut guest = export.guest.to_string();
    for component in relative.components() {
        let text = component.as_os_str().to_string_lossy();
        if text.is_empty() || text == "." {
            continue;
        }
        if !guest.ends_with('/') {
            guest.push('/');
        }
        guest.push_str(&text);
    }
    Ok(guest)
}

fn add_dir(
    exports: &mut Vec<Export>,
    tag: &'static str,
    guest: &'static str,
    dir: &Path,
    read_only: bool,
) -> Result<(), String> {
    let host = canonicalize(dir)?;
    if !host.is_dir() {
        return Err(format!("{} is not a directory", host.display()));
    }
    if exports.iter().any(|export| export.host == host) {
        return Ok(());
    }
    exports.push(Export {
        tag,
        host,
        guest,
        read_only,
    });
    Ok(())
}

fn add_file_parent(
    exports: &mut Vec<Export>,
    tag: &'static str,
    guest: &'static str,
    file: &Path,
    read_only: bool,
) -> Result<(), String> {
    let file = canonicalize(file)?;
    if !file.is_file() {
        return Err(format!("{} is not a file", file.display()));
    }
    let parent = file
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", file.display()))?;
    add_dir(exports, tag, guest, parent, read_only)
}

fn canonicalize(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|err| format!("{}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rob-share-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn rewrites_context_root_and_a_policy_file() {
        let root = scratch("tree");
        let context = root.join("ctx");
        let graph = root.join("graph");
        std::fs::create_dir_all(&context).unwrap();
        std::fs::create_dir_all(&graph).unwrap();
        let dockerfile = context.join("Dockerfile");
        std::fs::write(&dockerfile, "FROM scratch\n").unwrap();
        let policy = root.join("policy.json");
        std::fs::write(&policy, "{}\n").unwrap();

        let exports = plan_shares(ShareRequest {
            context: Some(&context),
            dockerfile: Some(&dockerfile),
            storage_root: Some(&graph),
            run_root: None,
            signature_policy: Some(&policy),
            registries_conf: None,
            auth_file: None,
        })
        .unwrap();
        assert!(exports.iter().any(|export| export.tag == TAG_CONTEXT));
        assert!(exports.iter().any(|export| export.tag == TAG_ROOT));
        assert!(exports.iter().any(|export| export.tag == TAG_POLICY));
        assert!(
            exports
                .iter()
                .find(|export| export.tag == TAG_CONTEXT)
                .unwrap()
                .read_only
        );
        assert!(
            !exports
                .iter()
                .find(|export| export.tag == TAG_ROOT)
                .unwrap()
                .read_only
        );
        assert!(
            !exports
                .iter()
                .find(|export| export.tag == TAG_POLICY)
                .unwrap()
                .read_only
        );

        let guest_docker = guest_path(&dockerfile, &exports).unwrap();
        assert_eq!(guest_docker, "/mnt/context/Dockerfile");
        let guest_graph = guest_path(&graph, &exports).unwrap();
        assert_eq!(guest_graph, "/mnt/root");
        let guest_policy = guest_path(&policy, &exports).unwrap();
        assert_eq!(guest_policy, "/mnt/policy/policy.json");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_a_dockerfile_outside_the_context() {
        let root = scratch("split");
        let context = root.join("ctx");
        let other = root.join("other");
        std::fs::create_dir_all(&context).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let dockerfile = other.join("Dockerfile");
        std::fs::write(&dockerfile, "FROM scratch\n").unwrap();
        let err = plan_shares(ShareRequest {
            context: Some(&context),
            dockerfile: Some(&dockerfile),
            storage_root: None,
            run_root: None,
            signature_policy: None,
            registries_conf: None,
            auth_file: None,
        })
        .unwrap_err();
        assert!(err.contains("outside"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn one_export_covers_a_policy_inside_the_context() {
        let root = scratch("inside");
        let context = root.join("ctx");
        std::fs::create_dir_all(&context).unwrap();
        let dockerfile = context.join("Dockerfile");
        let policy = context.join("policy.json");
        std::fs::write(&dockerfile, "FROM scratch\n").unwrap();
        std::fs::write(&policy, "{}\n").unwrap();
        let exports = plan_shares(ShareRequest {
            context: Some(&context),
            dockerfile: Some(&dockerfile),
            storage_root: None,
            run_root: None,
            signature_policy: Some(&policy),
            registries_conf: None,
            auth_file: None,
        })
        .unwrap();
        assert_eq!(exports.len(), 1);
        assert_eq!(
            guest_path(&policy, &exports).unwrap(),
            "/mnt/context/policy.json"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
