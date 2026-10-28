//! Shared helpers for OCI tooling.
//!
//! Signature helpers are always available. Guest attestation (`guest-embed`)
//! and macOS Virtualization host glue (`vm`) are feature-gated so product
//! crates can share them without merging their engines.

#![cfg_attr(not(all(feature = "vm", target_os = "macos")), forbid(unsafe_code))]

pub mod signature;

#[cfg(any(feature = "guest-embed", feature = "vm"))]
pub mod vm;
