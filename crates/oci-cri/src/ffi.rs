// SPDX-License-Identifier: Apache-2.0

//! C ABI of the Go engine shim (`shim/include/rok_abi.h`).
//!
//! The shim is a single Go c-archive: libcontainer and
//! containers/image+storage share one Go runtime (see `shim/main.go`). Every
//! engine operation is one JSON request in, one JSON response out, through
//! [`rok_call`]. Streaming output rides the stdio callback; interactive input
//! rides the input callback, which blocks until the caller supplies bytes.

#![allow(dead_code)]

use std::ffi::{c_char, c_void};

/// Callback for container stdout (`1`) and stderr (`2`).
pub(crate) type RokStdioFn =
    Option<unsafe extern "C" fn(user: *mut c_void, stream: i32, data: *const c_char, len: usize)>;

/// Callback that fills `buf` with stdin bytes. Returns the byte count, `0`
/// for EOF, or a negative value on error.
pub(crate) type RokInputFn =
    Option<unsafe extern "C" fn(user: *mut c_void, buf: *mut c_char, cap: usize) -> isize>;

#[repr(C)]
pub(crate) struct RokBuffer {
    pub data: *mut c_char,
    pub len: usize,
}

#[repr(C)]
pub(crate) struct RokError {
    pub code: i32,
    pub _pad: i32,
    pub message: RokBuffer,
    pub detail: RokBuffer,
}

impl RokBuffer {
    pub(crate) fn zero() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
        }
    }
}

impl RokError {
    pub(crate) fn zero() -> Self {
        Self {
            code: 0,
            _pad: 0,
            message: RokBuffer::zero(),
            detail: RokBuffer::zero(),
        }
    }
}

unsafe extern "C" {
    pub(crate) fn rok_startup(err: *mut RokError) -> i32;
    pub(crate) fn rok_call(
        request: *const c_char,
        stdio_fn: RokStdioFn,
        stdio_user: *mut c_void,
        input_fn: RokInputFn,
        input_user: *mut c_void,
        out: *mut RokBuffer,
        err: *mut RokError,
    ) -> i32;
    pub(crate) fn rok_diagnose(out: *mut RokBuffer, err: *mut RokError) -> i32;
    pub(crate) fn rok_buffer_free(buf: *mut RokBuffer);
    pub(crate) fn rok_error_free(err: *mut RokError);
}

#[cfg(test)]
mod abi_constants {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/abi_gen.rs"));
}

#[cfg(test)]
mod tests {
    use super::abi_constants::*;
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn layout_matches_c_header() {
        assert_eq!(size_of::<RokBuffer>(), ROK_BUFFER_SIZE);
        assert_eq!(align_of::<RokBuffer>(), ROK_BUFFER_ALIGN);
        assert_eq!(offset_of!(RokBuffer, data), ROK_BUFFER_OFF_DATA);
        assert_eq!(offset_of!(RokBuffer, len), ROK_BUFFER_OFF_LEN);
        assert_eq!(size_of::<RokError>(), ROK_ERROR_SIZE);
        assert_eq!(align_of::<RokError>(), ROK_ERROR_ALIGN);
    }
}
