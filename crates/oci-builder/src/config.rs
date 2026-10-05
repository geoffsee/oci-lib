// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

/// Process-wide storage and registry settings.
///
/// One process can open one store. Paths are optional: empty leaves the
/// containers/storage and containers/image defaults in place, including
/// `STORAGE_DRIVER` and the rootless graph root under the home directory.
#[derive(Debug, Clone)]
pub struct Config {
    /// Graph root. Created if it does not exist.
    pub storage_root: Option<PathBuf>,
    /// Run root for transient mount state.
    pub run_root: Option<PathBuf>,
    /// `vfs` needs no mount helper. `overlay` needs the kernel driver or fuse-overlayfs.
    pub storage_driver: Option<StorageDriver>,
    /// Driver options. When `storage_driver` is set, these replace storage.conf options.
    pub storage_opts: Vec<String>,
    /// Path to `registries.conf`.
    pub registries_conf: Option<PathBuf>,
    /// Path to a signature `policy.json`. Pulls fail closed when no policy can be found.
    pub signature_policy: Option<PathBuf>,
    /// Path to an auth file. Push can also take a username and password per call.
    pub auth_file: Option<PathBuf>,
    /// Allow HTTP registries and skip TLS verification for pulls made with this store.
    pub insecure: bool,
    /// Log level used for Buildah's own logger. Progress lines are separate.
    pub log_level: LogLevel,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            storage_root: None,
            run_root: None,
            storage_driver: None,
            storage_opts: Vec::new(),
            registries_conf: None,
            signature_policy: None,
            auth_file: None,
            insecure: false,
            log_level: LogLevel::Warn,
        }
    }
}

/// Local graph driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageDriver {
    /// Kernel overlay, or fuse-overlayfs when rootless.
    Overlay,
    /// Copies files. No mount helper, and the right driver for unprivileged tests.
    Vfs,
}

impl StorageDriver {
    pub(crate) fn as_abi(self) -> &'static str {
        match self {
            Self::Overlay => "overlay",
            Self::Vfs => "vfs",
        }
    }
}

/// Buildah log verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    /// Most verbose logging, including low-level engine details.
    Trace,
    /// Diagnostic information useful for debugging.
    Debug,
    /// Informational messages on normal progress.
    Info,
    /// Warning messages for non-fatal conditions.
    #[default]
    Warn,
    /// Error messages only.
    Error,
}

impl LogLevel {
    pub(crate) fn as_abi(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// How `RUN` instructions are executed.
///
/// `Default` follows `$BUILDAH_ISOLATION` and, when that is unset, uses
/// rootless isolation inside a user namespace and the default isolation as root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Isolation {
    /// Follow `$BUILDAH_ISOLATION` or platform defaults.
    #[default]
    Default,
    /// OCI runtime (runc or crun) in a separate namespace.
    Oci,
    /// Rootless OCI runtime.
    Rootless,
    /// `chroot` into the rootfs. Scratch and `COPY` builds do not need runc.
    Chroot,
}

impl Isolation {
    pub(crate) fn as_abi(self) -> &'static str {
        match self {
            Self::Default => "",
            Self::Oci => "oci",
            Self::Rootless => "rootless",
            Self::Chroot => "chroot",
        }
    }
}

/// Manifest format written by a build, or requested for a push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImageFormat {
    /// Open Container Initiative (OCI) image specification manifest.
    #[default]
    Oci,
    /// Docker schema 2.
    Docker,
}

impl ImageFormat {
    pub(crate) fn as_abi(self) -> &'static str {
        match self {
            Self::Oci => "oci",
            Self::Docker => "docker",
        }
    }
}

/// When a build may contact a registry for a base image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PullPolicy {
    /// Pull base image only if not present in local store.
    #[default]
    IfMissing,
    /// Always attempt to pull the latest image from the registry.
    Always,
    /// Pull if newer version is found in registry than local cache.
    IfNewer,
    /// Never contact registry; fail if base image is not present locally.
    Never,
}

impl PullPolicy {
    pub(crate) fn as_abi(self) -> &'static str {
        match self {
            Self::IfMissing => "missing",
            Self::Always => "always",
            Self::IfNewer => "ifnewer",
            Self::Never => "never",
        }
    }
}
