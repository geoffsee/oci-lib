// SPDX-License-Identifier: Apache-2.0

//! Run a rootfs with libcontainer.
//!
//! On Linux the engine is a Go c-archive linked into this process. There is
//! no `runc` binary on `PATH`. On macOS [`startup`] returns immediately and
//! [`Runtime::open`] runs that same Linux engine inside a
//! Virtualization.framework guest. Other operating systems link a stub and
//! [`startup`] returns [`ErrorCode::Unsupported`].
//!
//! Call [`startup`] before spawning threads or parsing arguments. libcontainer
//! re-executes this process to enter namespaces, and that child is dispatched
//! from the Go runtime before `main` continues.
//!
//! ```no_run
//! use oci_runner::{startup, RunRequest, Runtime};
//!
//! fn main() -> Result<(), oci_runner::Error> {
//!     startup()?;
//!     let runtime = Runtime::open()?;
//!     let status = runtime.run(&RunRequest::new("/path/to/rootfs", ["/bin/echo", "hi"]))?;
//!     runtime.shutdown()?;
//!     println!("status={status}");
//!     Ok(())
//! }
//! ```
//!
//! [`Runtime::shutdown`] stops the macOS guest. Dropping the [`Runtime`] does not.

#![warn(missing_docs)]

pub mod proto;
pub use proto as ror_proto;

#[cfg(ror_vm)]
mod entitlement;
mod error;
mod ffi;
#[cfg(any(ror_vm, test))]
mod guest_record;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(ror_vm)]
mod macos;
#[cfg(not(any(target_os = "linux", ror_vm)))]
mod other;
mod protocol_version;
mod request;
#[cfg(any(ror_vm, test))]
mod shares;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn ror_nsexec_keep() -> i32;
}

#[cfg(target_os = "linux")]
#[used]
static ROR_NSEXEC_KEEP: unsafe extern "C" fn() -> i32 = ror_nsexec_keep;

pub use error::{Error, ErrorCode};
pub use request::RunRequest;

use std::sync::Arc;

/// Callback for container stdout (`1`) and stderr (`2`).
pub type OutputFn = Arc<dyn Fn(u8, &[u8]) + Send + Sync>;

/// Check for a libcontainer re-exec, then return.
///
/// On Linux this calls into the shim. The `init` child never reaches this
/// function: Go `init` calls `libcontainer.Init` and does not return. On
/// macOS this does not boot a guest, so `--help` stays local. If the binary
/// lacks the `com.apple.security.virtualization` entitlement, it signs itself
/// ad hoc and re-executes with the same arguments (`ROR_NO_SELF_SIGN=1`
/// turns that off).
pub fn startup() -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        linux::startup()
    }
    #[cfg(ror_vm)]
    {
        entitlement::ensure();
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", ror_vm)))]
    {
        other::startup()
    }
}

/// One open runtime in this process.
///
/// On Linux that is a flag. On macOS it owns the guest thread. Dropping it
/// does not shut the guest down.
pub struct Runtime {
    _private: (),
}

impl Runtime {
    /// Open the runtime.
    ///
    /// On Linux this initialises the engine in the current process. On macOS
    /// this boots the lightweight virtual machine guest.
    pub fn open() -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        {
            linux::open()?;
            Ok(Self { _private: () })
        }
        #[cfg(ror_vm)]
        {
            macos::open()?;
            Ok(Self { _private: () })
        }
        #[cfg(not(any(target_os = "linux", ror_vm)))]
        {
            other::startup()?;
            Ok(Self { _private: () })
        }
    }

    /// Run a container. Standard streams are inherited on Linux. On macOS
    /// they are copied from the guest onto this process.
    pub fn run(&self, request: &RunRequest) -> Result<i32, Error> {
        self.run_with(request, None)
    }

    /// Run a container and receive stdout and stderr through `on_output`.
    ///
    /// `None` inherits the process streams on Linux and writes the guest
    /// streams to this process on macOS. The callback may run on a Go thread.
    /// It must not call back into [`Runtime`] and it must not unwind.
    pub fn run_with(
        &self,
        request: &RunRequest,
        on_output: Option<OutputFn>,
    ) -> Result<i32, Error> {
        let prepared = request.prepare()?;
        #[cfg(target_os = "linux")]
        {
            linux::run(&prepared, on_output)
        }
        #[cfg(ror_vm)]
        {
            macos::run(&prepared, on_output)
        }
        #[cfg(not(any(target_os = "linux", ror_vm)))]
        {
            let _ = (prepared, on_output);
            Err(other::unsupported())
        }
    }

    /// Shut down the runtime.
    ///
    /// On macOS this stops the virtual machine guest and releases resources.
    /// On Linux this resets the runtime state.
    pub fn shutdown(self) -> Result<(), Error> {
        #[cfg(target_os = "linux")]
        {
            linux::shutdown()
        }
        #[cfg(ror_vm)]
        {
            macos::shutdown()
        }
        #[cfg(not(any(target_os = "linux", ror_vm)))]
        {
            Ok(())
        }
    }

    /// Report whether this host can run a container.
    ///
    /// A blocked report is returned as [`ErrorCode::Prerequisite`] with the
    /// text in [`Error::detail`].
    pub fn diagnose() -> Result<String, Error> {
        #[cfg(target_os = "linux")]
        {
            linux::diagnose()
        }
        #[cfg(ror_vm)]
        {
            macos::diagnose()
        }
        #[cfg(not(any(target_os = "linux", ror_vm)))]
        {
            other::diagnose()
        }
    }
}

// The stub has no engine to start, so these tests need Linux or the macOS guest.
#[cfg(all(test, any(target_os = "linux", ror_vm)))]
mod tests {
    use super::*;

    #[test]
    fn startup_does_not_boot_a_guest() {
        startup().expect("startup");
    }

    #[cfg(ror_vm)]
    #[test]
    fn diagnose_without_a_guest_image_is_a_prerequisite_error() {
        match Runtime::diagnose() {
            Ok(report) => {
                assert!(report.contains("status: ready"));
            }
            Err(err) => {
                assert_eq!(err.code(), ErrorCode::Prerequisite);
                assert!(err.detail().contains("status: blocked"));
            }
        }
    }
}
