// SPDX-License-Identifier: Apache-2.0

//! Version of the host/guest virtio-vsock protocol.

/// Current host/guest wire-protocol version. Shares the value the other
/// crates use so `cargo xtask guest` attests every guest uniformly.
pub const PROTOCOL_VERSION: u32 = 2;
