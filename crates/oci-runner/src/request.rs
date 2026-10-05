// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, ErrorCode};

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const HOST_NAME_MAX: usize = 64;

/// One foreground container.
#[derive(Debug, Clone)]
pub struct RunRequest {
    /// Directory containing the root filesystem of the container.
    pub rootfs: PathBuf,
    /// The command and arguments to execute.
    pub argv: Vec<String>,
    /// Environment variables to set inside the container as `(key, value)` pairs.
    pub env: Vec<(String, String)>,
    /// Initial working directory inside the container. Must be an absolute path.
    pub cwd: String,
    /// Hostname assigned inside the container's UTS namespace.
    pub hostname: String,
    /// Optional directory where runtime state and lock files are placed on Linux.
    ///
    /// On macOS, the host directory is created and validated while the guest uses
    /// its own internal state root.
    pub state_root: Option<PathBuf>,
    /// Whether to unshare the network namespace (creates a private loopback).
    pub isolate_network: bool,
}

/// Checked request. Paths are absolute.
#[derive(Debug, Clone)]
pub(crate) struct PreparedRun {
    pub rootfs: PathBuf,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub hostname: String,
    /// Linux passes this into the shim. The macOS guest keeps its own directory.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub state_root: Option<PathBuf>,
    pub isolate_network: bool,
}

impl RunRequest {
    /// Create a new container run request for the given rootfs and command.
    pub fn new(
        rootfs: impl Into<PathBuf>,
        argv: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            rootfs: rootfs.into(),
            argv: argv.into_iter().map(Into::into).collect(),
            env: Vec::new(),
            cwd: "/".to_string(),
            hostname: "runner".to_string(),
            state_root: None,
            isolate_network: false,
        }
    }

    /// Add an environment variable to the container.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Set the container working directory (must be an absolute path).
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = cwd.into();
        self
    }

    /// Set the container hostname.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self
    }

    /// Set an explicit directory for runtime state on Linux.
    ///
    /// On macOS, the supplied host directory is created and validated while
    /// the guest keeps its own internal state directory.
    pub fn state_root(mut self, state_root: impl Into<PathBuf>) -> Self {
        self.state_root = Some(state_root.into());
        self
    }

    /// Configure whether network namespace isolation is enabled.
    pub fn isolate_network(mut self, isolate: bool) -> Self {
        self.isolate_network = isolate;
        self
    }

    pub(crate) fn prepare(&self) -> Result<PreparedRun, Error> {
        if self.argv.is_empty() || self.argv.iter().any(|arg| arg.is_empty()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "command is empty",
                "",
            ));
        }
        if self.argv.iter().any(|arg| arg.contains('\0')) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "command contains a NUL byte",
                "",
            ));
        }
        if self.cwd.is_empty() || !self.cwd.starts_with('/') {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "cwd must be an absolute path",
                "",
            ));
        }
        if self.hostname.is_empty() || self.hostname.len() > HOST_NAME_MAX {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "hostname must be 1 to 64 bytes",
                "",
            ));
        }
        if self.hostname.contains('\0') {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "hostname contains a NUL byte",
                "",
            ));
        }
        let rootfs = canonicalize_dir(&self.rootfs)?;
        let state_root = match &self.state_root {
            None => None,
            Some(path) => {
                std::fs::create_dir_all(path).map_err(|err| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("state directory {}: {err}", path.display()),
                        "",
                    )
                })?;
                Some(canonicalize_dir(path)?)
            }
        };
        Ok(PreparedRun {
            rootfs,
            argv: self.argv.clone(),
            env: merge_env(&self.env)?,
            cwd: self.cwd.clone(),
            hostname: self.hostname.clone(),
            state_root,
            isolate_network: self.isolate_network,
        })
    }
}

fn canonicalize_dir(path: &Path) -> Result<PathBuf, Error> {
    let canon = path.canonicalize().map_err(|err| {
        let code = if err.kind() == std::io::ErrorKind::NotFound {
            ErrorCode::NotFound
        } else {
            ErrorCode::InvalidArgument
        };
        Error::new(code, format!("{}: {err}", path.display()), "")
    })?;
    if !canon.is_dir() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{} is not a directory", canon.display()),
            "",
        ));
    }
    Ok(canon)
}

fn merge_env(pairs: &[(String, String)]) -> Result<Vec<String>, Error> {
    let mut map = BTreeMap::new();
    map.insert("PATH".to_string(), DEFAULT_PATH.to_string());
    map.insert("HOME".to_string(), "/root".to_string());
    for (key, value) in pairs {
        if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("environment entry {key} is not a usable KEY=VALUE"),
                "",
            ));
        }
        map.insert(key.clone(), value.clone());
    }
    Ok(map
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_empty_command_and_a_relative_cwd() {
        let err = RunRequest::new("/no/such", Vec::<String>::new())
            .prepare()
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);

        let dir = std::env::temp_dir().join(format!(
            "ror-req-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let err = RunRequest::new(&dir, ["/bin/true"])
            .cwd("relative")
            .prepare()
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let err = RunRequest::new(&dir, ["/bin/true"])
            .env("=bad", "x")
            .prepare()
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let prepared = RunRequest::new(&dir, ["/bin/true"])
            .env("FOO", "bar")
            .prepare()
            .unwrap();
        assert!(prepared.env.iter().any(|item| item == "FOO=bar"));
        assert!(prepared.env.iter().any(|item| item.starts_with("PATH=")));
        assert_eq!(prepared.hostname, "runner");
        assert!(!prepared.isolate_network);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_rootfs_is_not_found() {
        let err = RunRequest::new("/no/such/oci-runner-rootfs", ["/bin/true"])
            .prepare()
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }
}
