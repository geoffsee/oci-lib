// SPDX-License-Identifier: Apache-2.0

//! The `com.apple.security.virtualization` entitlement.
//!
//! macOS reads entitlements from the code signature, so a binary built
//! outside this repo's cargo wrappers (`cargo install`, a dependent crate)
//! has none and cannot boot the guest. `startup` signs the executable ad hoc
//! with the plist below and re-executes it with the same arguments.
//! `ROR_NO_SELF_SIGN=1` turns that off.

use std::ffi::c_void;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;
use std::{env, fs};

use objc2::rc::Retained;
use objc2_foundation::NSString;

use crate::error::{Error, ErrorCode};

const ENTITLEMENT: &str = "com.apple.security.virtualization";

const ENTITLEMENTS_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.virtualization</key>
	<true/>
</dict>
</plist>
"#;

/// Set on the re-executed process so a signature that still lacks the
/// entitlement does not loop.
const RESIGNED: &str = "OCI_LIB_RESIGNED";

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTaskCreateFromSelf(allocator: *const c_void) -> *mut c_void;
    fn SecTaskCopyValueForEntitlement(
        task: *mut c_void,
        entitlement: *const c_void,
        error: *mut *mut c_void,
    ) -> *const c_void;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFBooleanTrue: *const c_void;
    fn CFRelease(value: *const c_void);
}

/// Whether the running process carries the entitlement.
pub(crate) fn present() -> bool {
    unsafe {
        let task = SecTaskCreateFromSelf(std::ptr::null());
        if task.is_null() {
            return false;
        }
        let name: Retained<NSString> = NSString::from_str(ENTITLEMENT);
        let key = Retained::as_ptr(&name) as *const c_void;
        let value = SecTaskCopyValueForEntitlement(task, key, std::ptr::null_mut());
        let granted = !value.is_null() && value == kCFBooleanTrue;
        if !value.is_null() {
            CFRelease(value);
        }
        CFRelease(task);
        granted
    }
}

/// Sign the executable and re-execute it when the entitlement is missing.
/// Returns only when nothing needed doing or signing was not possible; the
/// guest boot then reports the missing entitlement.
pub(crate) fn ensure() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if present() || env::var_os("ROR_NO_SELF_SIGN").is_some() || env::var_os(RESIGNED).is_some()
        {
            return;
        }
        let Ok(exe) = env::current_exe() else {
            return;
        };
        if sign(&exe).is_err() {
            return;
        }
        let err = Command::new(&exe)
            .args(env::args_os().skip(1))
            .env(RESIGNED, "1")
            .exec();
        eprintln!("re-executing {} after signing it: {err}", exe.display());
    });
}

/// Sign a copy beside the executable, then rename it over the original. The
/// running process keeps the old file, so its pages are never rewritten.
fn sign(exe: &Path) -> std::io::Result<()> {
    let dir = exe.parent().unwrap_or(Path::new("."));
    let name = exe.file_name().unwrap_or_default().to_string_lossy();
    let copy = dir.join(format!(".{name}.signing-{}", std::process::id()));
    let plist = plist_file()?;
    let result = fs::copy(exe, &copy).and_then(|_| {
        let output = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--entitlements"])
            .arg(&plist)
            .arg(&copy)
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        fs::rename(&copy, exe)
    });
    let _ = fs::remove_file(&plist);
    if result.is_err() {
        let _ = fs::remove_file(&copy);
    }
    result
}

fn plist_file() -> std::io::Result<PathBuf> {
    let path = env::temp_dir().join(format!("oci-lib-entitlements-{}.plist", std::process::id()));
    fs::write(&path, ENTITLEMENTS_PLIST)?;
    Ok(path)
}

/// The error a boot returns without the entitlement, with the command that
/// fixes it.
pub(crate) fn missing() -> Error {
    let exe = env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<binary>".into());
    Error::new(
        ErrorCode::Prerequisite,
        format!("this binary lacks the {ENTITLEMENT} entitlement"),
        format!(
            "startup() could not sign it (or ROR_NO_SELF_SIGN is set). Sign it with an entitlements plist that sets {ENTITLEMENT} to true:\n  codesign --force --sign - --entitlements entitlements.plist {exe}"
        ),
    )
}
