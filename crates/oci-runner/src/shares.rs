// SPDX-License-Identifier: Apache-2.0

//! Host rootfs export for the Linux guest.

use std::path::{Path, PathBuf};

pub const TAG_ROOTFS: &str = "rootfs";
pub const GUEST_ROOTFS: &str = "/mnt/rootfs";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub tag: &'static str,
    pub host: PathBuf,
    pub guest: &'static str,
}

pub fn export_rootfs(rootfs: &Path) -> Result<Export, String> {
    let host = canonicalize(rootfs)?;
    if !host.is_dir() {
        return Err(format!("{} is not a directory", host.display()));
    }
    Ok(Export {
        tag: TAG_ROOTFS,
        host,
        guest: GUEST_ROOTFS,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn guest_path(path: &Path, export: &Export) -> Result<String, String> {
    let path = canonicalize(path)?;
    if !path.starts_with(&export.host) {
        return Err(format!(
            "{} is not inside {}",
            path.display(),
            export.host.display()
        ));
    }
    let relative = path.strip_prefix(&export.host).map_err(|e| e.to_string())?;
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

fn canonicalize(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|err| format!("{}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_rootfs_to_guest_path() {
        let root = std::env::temp_dir().join(format!(
            "ror-share-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let export = export_rootfs(&root).unwrap();
        assert_eq!(guest_path(&root, &export).unwrap(), "/mnt/rootfs");
        let _ = std::fs::remove_dir_all(&root);
    }
}
