// SPDX-License-Identifier: Apache-2.0

//! Runs the CLI out of process. libcontainer re-execs the caller, so this
//! must not be a unit test inside the `oci-runner` binary.

#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
fn bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_oci-runner")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let exe = std::env::current_exe().expect("test executable");
            exe.parent()
                .and_then(|dir| dir.parent())
                .map(|dir| dir.join(format!("oci-runner{}", std::env::consts::EXE_SUFFIX)))
                .expect("oci-runner beside the test harness")
        })
}

#[cfg(target_os = "linux")]
#[test]
fn runs_true_against_the_host_root() {
    if std::env::var("ROR_TEST_HOST_ROOT").ok().as_deref() != Some("1") {
        eprintln!("skip: set ROR_TEST_HOST_ROOT=1 to run /bin/true in rootfs /");
        return;
    }
    let status = std::process::Command::new(bin())
        .args(["run", "--rootfs", "/", "--", "/bin/true"])
        .status()
        .expect("spawn oci-runner");
    assert!(status.success(), "oci-runner status {status}");
}
