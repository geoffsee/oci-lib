// SPDX-License-Identifier: Apache-2.0

//! Product identity for guest embed and Virtualization host sessions.

use std::time::Duration;

/// Runtime identity for a product's macOS guest session.
#[derive(Debug, Clone, Copy)]
pub struct GuestConfig {
    /// Crate / product name (`oci-runner`, `oci-builder`, …).
    pub product_name: &'static str,
    /// Virtio-vsock port the in-guest agent listens on.
    pub vsock_port: u32,
    /// Host/guest wire protocol version for this product.
    pub protocol_version: u32,
    /// Dispatch queue label for the virtual machine.
    pub queue_label: &'static str,
    /// Worker thread name.
    pub thread_name: &'static str,
    /// Console drain thread name.
    pub console_thread_name: &'static str,
    /// `~/Library/Caches/<this>` directory name for materialized guest images.
    pub cache_dir_name: &'static str,
    /// Env var that disables entitlement self-sign (`ROR_NO_SELF_SIGN`, …).
    pub no_self_sign_env: &'static str,
    /// How long to wait for the VM to start and accept a vsock connection.
    pub boot_timeout: Duration,
    /// How long to wait for the protocol hello after connect.
    pub handshake_timeout: Duration,
    /// Linux kernel command line.
    pub kernel_cmdline: &'static str,
}

impl GuestConfig {
    /// Defaults shared by the current product guests.
    pub const fn base(
        product_name: &'static str,
        vsock_port: u32,
        protocol_version: u32,
        no_self_sign_env: &'static str,
    ) -> Self {
        Self {
            product_name,
            vsock_port,
            protocol_version,
            queue_label: "",
            thread_name: "",
            console_thread_name: "",
            cache_dir_name: product_name,
            no_self_sign_env,
            boot_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(5),
            kernel_cmdline: "console=hvc0 reboot=k panic=1 init=/init",
        }
    }
}

/// Build-script identity for embedding a guest into `OUT_DIR`.
#[derive(Debug, Clone, Copy)]
pub struct EmbedConfig {
    /// `CARGO_PKG_NAME` override when not reading from the environment.
    pub package: Option<&'static str>,
    /// Env var for an explicit kernel path.
    pub kernel_env: &'static str,
    /// Env var for an explicit initramfs path.
    pub initrd_env: &'static str,
    /// Env var for the download cache root.
    pub cache_env: &'static str,
    /// `OUT_DIR` filename for the zstd kernel (`ror-guest-vmlinuz.zst`, …).
    pub out_kernel_name: &'static str,
    /// `OUT_DIR` filename for the zstd initramfs.
    pub out_initrd_name: &'static str,
    /// `OUT_DIR` filename for the attestation JSON.
    pub out_attestation_name: &'static str,
    /// Host/guest protocol version recorded in the attestation check.
    pub protocol_version: u32,
}
