// SPDX-License-Identifier: Apache-2.0

//! Product identity for the oci-cri macOS guest.

use std::time::Duration;

use oci_util::vm::GuestConfig;

use crate::proto::VSOCK_PORT;
use crate::protocol_version::PROTOCOL_VERSION;

/// CRI guest session identity.
pub const GUEST: GuestConfig = GuestConfig {
    product_name: "oci-cri",
    vsock_port: VSOCK_PORT,
    protocol_version: PROTOCOL_VERSION,
    queue_label: "oci-cri.vm",
    thread_name: "oci-cri-guest",
    console_thread_name: "oci-cri-console",
    cache_dir_name: "oci-cri",
    no_self_sign_env: "ROK_NO_SELF_SIGN",
    boot_timeout: Duration::from_secs(60),
    handshake_timeout: Duration::from_secs(10),
    kernel_cmdline: "console=hvc0 reboot=k panic=1 init=/init",
};
