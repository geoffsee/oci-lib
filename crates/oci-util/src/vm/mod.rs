//! Shared macOS guest packaging and Virtualization host helpers.
//!
//! Product crates keep their own Go shims and wire protocols. This module
//! holds the duplicated host glue: entitlement self-sign, attestation parse
//! and check, virtiofs share planning, guest image embed, and VZ boot/vsock.

mod attest;
mod check;
mod config;
mod record;

pub use attest::{Attestation, parse as parse_attestation};
pub use check::{compatibility_match, hashes_match, version_requires_guest_attestation};
pub use config::{EmbedConfig, GuestConfig};
pub use record::lines_from_attestation;

#[cfg(feature = "guest-embed")]
mod embed;
#[cfg(feature = "guest-embed")]
pub use embed::embed_guest;

#[cfg(all(feature = "vm", target_os = "macos"))]
mod entitlement;
#[cfg(all(feature = "vm", target_os = "macos"))]
mod error;
#[cfg(all(feature = "vm", target_os = "macos"))]
mod host;
#[cfg(all(feature = "vm", target_os = "macos"))]
mod shares;

#[cfg(all(feature = "vm", target_os = "macos"))]
pub use entitlement::{
    ensure as ensure_entitlement, missing as missing_entitlement, present as entitlement_present,
};
#[cfg(all(feature = "vm", target_os = "macos"))]
pub use error::{VmError, VmErrorKind};
#[cfg(all(feature = "vm", target_os = "macos"))]
pub use host::{
    BootedVm, StartedVm, boot_vm, connect_guest_vsock, materialize_embedded, start_vm,
    stop_virtual_machine, virtualization_supported, wait_readable,
};
#[cfg(all(feature = "vm", target_os = "macos"))]
pub use shares::{
    Export, GUEST_AUTH, GUEST_CONTEXT, GUEST_POLICY, GUEST_REGISTRIES, GUEST_ROOT, GUEST_ROOTFS,
    GUEST_RUNROOT, ShareRequest, TAG_AUTH, TAG_CONTEXT, TAG_POLICY, TAG_REGISTRIES, TAG_ROOT,
    TAG_ROOTFS, TAG_RUNROOT, add_dir, add_file_parent, export_rootfs, guest_path, plan_shares,
};
