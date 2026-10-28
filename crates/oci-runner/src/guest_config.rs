// SPDX-License-Identifier: Apache-2.0

//! Product identity for the oci-runner macOS guest.

use std::time::Duration;

use oci_util::vm::GuestConfig;

use crate::proto::VSOCK_PORT;
use crate::protocol_version::PROTOCOL_VERSION;

/// Runtime guest session identity.
pub const GUEST: GuestConfig = GuestConfig {
    product_name: "oci-runner",
    vsock_port: VSOCK_PORT,
    protocol_version: PROTOCOL_VERSION,
    queue_label: "oci-runner.vm",
    thread_name: "oci-runner-guest",
    console_thread_name: "oci-runner-console",
    cache_dir_name: "oci-runner",
    no_self_sign_env: "ROR_NO_SELF_SIGN",
    boot_timeout: Duration::from_secs(30),
    handshake_timeout: Duration::from_secs(5),
    kernel_cmdline: "console=hvc0 reboot=k panic=1 init=/init",
};
