// SPDX-License-Identifier: Apache-2.0

//! Constants for the macOS host/guest virtio-vsock byte proxy.
//!
//! Unlike `oci-runner`, the CRI host does not frame container runs: the CRI
//! connection itself is a byte stream, so each unix-socket connection accepted
//! on the host is proxied 1:1 onto one vsock connection to the guest, where
//! `--engine-serve` terminates gRPC. The only framing is the negotiation
//! below, used once per VM boot so a stale guest fails fast.

pub use crate::protocol_version::PROTOCOL_VERSION;

/// Guest virtio-vsock port the agent listens on. The host connects to it.
pub const VSOCK_PORT: u32 = 5254;

/// Magic the guest writes on each accepted connection before proxying, so the
/// host can tell a live agent from a half-booted kernel.
pub const GUEST_BANNER: &[u8; 8] = b"ROKCRI1\n";
