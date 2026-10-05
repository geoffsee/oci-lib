// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::ffi;

pub(crate) fn startup() -> Result<(), Error> {
    let mut err = ffi::RorError::zero();
    let rc = unsafe { ffi::ror_startup(&mut err) };
    if rc == 0 {
        return Ok(());
    }
    let code = crate::error::ErrorCode::from_raw(err.code);
    let message = unsafe { read_buf(&err.message) };
    let detail = unsafe { read_buf(&err.detail) };
    unsafe { ffi::ror_error_free(&mut err) };
    Err(Error::new(code, message, detail))
}

pub(crate) fn diagnose() -> Result<String, Error> {
    Err(Error::new(
        crate::error::ErrorCode::Unsupported,
        "oci-runner is available on Linux and macOS only",
        "",
    ))
}

unsafe fn read_buf(buf: &ffi::RorBuffer) -> String {
    if buf.data.is_null() || buf.len == 0 {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.data as *const u8, buf.len) };
    String::from_utf8_lossy(bytes).into_owned()
}
