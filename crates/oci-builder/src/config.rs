// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
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
    /// Path to a signature `policy.json`.
    ///
    /// `None` with the `default-policy` feature (on by default) uses an
    /// embedded containers-common policy, written to a temporary file for
    /// this process: the default requirement is `reject`, the `docker`
    /// transport for hostname `localhost` is `insecureAcceptAnything`, and
    /// the `docker-daemon` transport with an empty host is
    /// `insecureAcceptAnything`. That is not a global
    /// `insecureAcceptAnything`. A path set here is used as-is.
    /// Without the feature, `None` leaves discovery to containers/image,
    /// which fails closed when no policy file exists.
    pub signature_policy: Option<PathBuf>,
    /// Path to an auth file. Push can also take a username and password per call.
    pub auth_file: Option<PathBuf>,
    /// Allow HTTP registries and skip TLS verification for pulls made with this store.
    pub insecure: bool,
    /// Log level used for Buildah's own logger. Progress lines are separate.
    pub log_level: LogLevel,
    /// Path to a PKCS8 private key for signing pushed images with Notary.
    /// When set, images are signed after push.
    pub signing_key: Option<PathBuf>,
    /// Paths to certificate chain files (DER encoded) for Notary signatures.
    /// Leaf certificate comes first. Required when signing_key is set.
    pub signing_cert_chain: Vec<PathBuf>,
    /// Path to a Notary trust policy used to verify OCI referrers before pulls.
    pub trust_policy: Option<PathBuf>,
    /// DER trust anchors keyed by trust-store name (`ca:name` or
    /// `signingAuthority:name`).
    pub trust_anchors: BTreeMap<String, Vec<PathBuf>>,
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
            signing_key: None,
            signing_cert_chain: Vec::new(),
            trust_policy: None,
            trust_anchors: BTreeMap::new(),
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
/// On the macOS guest, `Default` is sent as `chroot` and `Oci` / `Rootless`
/// are rejected before the VM starts: that guest has no OCI runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Isolation {
    /// Follow `$BUILDAH_ISOLATION` or platform defaults.
    ///
    /// On the macOS guest this is sent as `chroot`. On Linux it stays the
    /// engine default.
    #[default]
    Default,
    /// OCI runtime (runc or crun) in a separate namespace.
    ///
    /// Rejected on the macOS guest before the VM starts.
    Oci,
    /// Rootless OCI runtime.
    ///
    /// Rejected on the macOS guest before the VM starts.
    Rootless,
    /// `chroot` into the rootfs. Scratch and `COPY` builds do not need runc.
    ///
    /// This is the supported isolation for the macOS guest.
    Chroot,
}

/// Which engine a build will talk to. Linux behavior stays on [`Isolation::as_abi`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineHost {
    /// Apple Virtualization Linux guest. No `runc` or `crun`.
    #[cfg_attr(not(any(rob_vm, test)), allow(dead_code))]
    MacosGuest,
    /// In-process Linux engine.
    Linux,
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

    /// Isolation string for this host.
    ///
    /// `MacosGuest` maps `Default` and `Chroot` to `chroot` and returns an
    /// error for `Oci` and `Rootless`. `Linux` is [`Self::as_abi`], so
    /// `Default` stays the engine default (an empty string) and is not rewritten.
    pub(crate) fn for_engine(self, host: EngineHost) -> Result<&'static str, crate::error::Error> {
        match host {
            EngineHost::Linux => Ok(self.as_abi()),
            EngineHost::MacosGuest => match self {
                Self::Default | Self::Chroot => Ok("chroot"),
                Self::Oci | Self::Rootless => Err(crate::error::Error::new(
                    crate::error::ErrorCode::Unsupported,
                    "this guest has no OCI runtime; chroot is the supported isolation",
                    "",
                )),
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_guest_defaults_to_chroot_and_rejects_oci() {
        assert_eq!(
            Isolation::Default
                .for_engine(EngineHost::MacosGuest)
                .unwrap(),
            "chroot"
        );
        assert_eq!(
            Isolation::Chroot
                .for_engine(EngineHost::MacosGuest)
                .unwrap(),
            "chroot"
        );
        for isolation in [Isolation::Oci, Isolation::Rootless] {
            let err = isolation.for_engine(EngineHost::MacosGuest).unwrap_err();
            let text = err.to_string();
            assert!(
                text.contains("no OCI runtime"),
                "missing runtime note: {text}"
            );
            assert!(
                text.contains("chroot is the supported isolation"),
                "missing chroot note: {text}"
            );
        }
    }

    #[test]
    fn linux_default_stays_the_engine_default() {
        assert_eq!(
            Isolation::Default.for_engine(EngineHost::Linux).unwrap(),
            Isolation::Default.as_abi()
        );
        assert_eq!(Isolation::Default.as_abi(), "");
        assert_eq!(Isolation::Oci.for_engine(EngineHost::Linux).unwrap(), "oci");
        assert_eq!(
            Isolation::Rootless.for_engine(EngineHost::Linux).unwrap(),
            "rootless"
        );
        assert_eq!(
            Isolation::Chroot.for_engine(EngineHost::Linux).unwrap(),
            "chroot"
        );
    }
}
