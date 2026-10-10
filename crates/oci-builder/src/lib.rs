// SPDX-License-Identifier: Apache-2.0

//! Embed Buildah in a Rust process.
//!
//! The engine is a Go c-archive behind a small C ABI. This crate exposes that
//! ABI as [`Builder::build`] and [`Builder::push`]. There is no Buildah daemon
//! and no `buildah` executable on `PATH`.
//!
//! On Linux, [`startup`] must be the first call in `main`, before threads are
//! created and before arguments are parsed. Buildah re-executes the process
//! for rootless user namespaces and for its own helper commands. On macOS,
//! [`startup`] returns immediately and [`Builder::open`] runs that same Linux
//! engine inside a Virtualization.framework guest. Other operating systems
//! link a stub and [`startup`] returns [`ErrorCode::Unsupported`].
//!
//! ```no_run
//! use oci_builder::{startup, BuildRequest, Builder, Config, StorageDriver};
//!
//! fn main() -> Result<(), oci_builder::Error> {
//!     startup()?;
//!     let builder = Builder::open(Config {
//!         storage_driver: Some(StorageDriver::Vfs),
//!         ..Config::default()
//!     })?;
//!     let info = builder.build(
//!         BuildRequest::new("Dockerfile", ".").with_log(|record| {
//!             eprint!("{}", record.message);
//!         }),
//!     )?;
//!     println!("image_id={}", info.image_id);
//!     builder.shutdown()?;
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]

pub mod proto;
pub use proto as rob_proto;

mod builder;
mod config;
#[cfg(rob_vm)]
mod entitlement;
mod error;
mod ffi;
#[cfg(rob_vm)]
mod macos;
#[cfg(any(rob_vm, test))]
mod shares;

// Pull native/unshare_early.c into the link so its constructor runs.
#[cfg(not(rob_stub))]
unsafe extern "C" {
    fn rob_unshare_keep() -> i32;
}

#[cfg(not(rob_stub))]
#[used]
static ROB_UNSHARE_KEEP: unsafe extern "C" fn() -> i32 = rob_unshare_keep;

pub use builder::{
    BuildRequest, Builder, CancelToken, ImageInfo, LogRecord, LogStream, PushRequest,
    buildah_version, startup,
};
pub use config::{Config, ImageFormat, Isolation, LogLevel, PullPolicy, StorageDriver};
pub use error::{Error, ErrorCode};
