// SPDX-License-Identifier: Apache-2.0

//! Version of the host/guest virtio-vsock protocol.
//!
//! Bump this whenever a frame changes in a way that an older guest cannot
//! decode. The value is shared with `cargo xtask guest` so an initramfs
//! attestation records the protocol its executable was built for.

/// Current host/guest wire-protocol version.
pub const PROTOCOL_VERSION: u32 = 2;
