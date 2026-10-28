// SPDX-License-Identifier: Apache-2.0

//! Runtime-owned resolver files, shared by all containers in one sandbox.
use std::path::{Path, PathBuf};

use crate::api::DnsConfig;
use crate::error::{Error, ErrorCode, Result};

pub(crate) fn path(root: &Path, id: &str) -> PathBuf {
    root.join("dns").join(format!("{id}.conf"))
}

fn io_error(err: std::io::Error) -> Error {
    Error::new(
        ErrorCode::Internal,
        "sandbox resolver file",
        err.to_string(),
    )
}

pub(crate) struct Resolver {
    path: Option<PathBuf>,
    committed: bool,
}

impl Resolver {
    pub(crate) fn create(root: &Path, id: &str, config: Option<&DnsConfig>) -> Result<Self> {
        let Some(config) = config else {
            return Ok(Self {
                path: None,
                committed: false,
            });
        };
        // Values are individual resolv.conf tokens, not extra directives.
        for value in config
            .servers
            .iter()
            .chain(&config.searches)
            .chain(&config.options)
        {
            if value.is_empty() || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "invalid DNS configuration token",
                    "",
                ));
            }
        }
        let mut text = String::new();
        for server in &config.servers {
            text.push_str(&format!("nameserver {server}\n"));
        }
        if !config.searches.is_empty() {
            text.push_str(&format!("search {}\n", config.searches.join(" ")));
        }
        if !config.options.is_empty() {
            text.push_str(&format!("options {}\n", config.options.join(" ")));
        }
        let file = path(root, id);
        std::fs::create_dir_all(root.join("dns")).map_err(io_error)?;
        // Never write through paths or symlinks from an untrusted image rootfs.
        let guard = Self {
            path: Some(file.clone()),
            committed: false,
        };
        std::fs::write(file, text).map_err(io_error)?;
        Ok(guard)
    }

    pub(crate) fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(path) = &self.path {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

pub(crate) fn mount(spec: String, root: &Path, id: &str) -> Result<String> {
    let path = path(root, id);
    if !path.try_exists().map_err(io_error)? {
        return Ok(spec);
    }
    let json_error = |err: serde_json::Error| {
        Error::new(
            ErrorCode::Internal,
            "sandbox resolver mount",
            err.to_string(),
        )
    };
    let mut spec: serde_json::Value = serde_json::from_str(&spec).map_err(json_error)?;
    if let Some(mounts) = spec["mounts"].as_array_mut() {
        for mount in mounts {
            if mount["destination"] == "/etc/resolv.conf" {
                mount["source"] = serde_json::json!(path);
            }
        }
    }
    serde_json::to_string(&spec).map_err(json_error)
}

pub(crate) fn remove(root: &Path, id: &str) -> Result<()> {
    match std::fs::remove_file(path(root, id)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_error(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_and_io_errors_are_not_silenced() {
        let dir = tempfile::tempdir().unwrap();
        let config = DnsConfig {
            servers: vec!["10.43.0.10".into()],
            ..Default::default()
        };
        let guard = Resolver::create(dir.path(), "sandbox", Some(&config)).unwrap();
        assert!(path(dir.path(), "sandbox").exists());
        drop(guard);
        assert!(!path(dir.path(), "sandbox").exists());
        std::fs::write(dir.path().join("file"), "not a directory").unwrap();
        assert!(Resolver::create(&dir.path().join("file"), "sandbox", Some(&config)).is_err());
        let injected = DnsConfig {
            servers: vec!["10.0.0.1\nsearch bad".into()],
            ..Default::default()
        };
        assert!(Resolver::create(dir.path(), "sandbox", Some(&injected)).is_err());
        assert!(!path(dir.path(), "sandbox").exists());
    }
}
