// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use std::ffi::{c_char, c_void};

pub(crate) type RorStdioFn =
    Option<unsafe extern "C" fn(user: *mut c_void, stream: i32, data: *const c_char, len: usize)>;

#[repr(C)]
pub(crate) struct RorBuffer {
    pub data: *mut c_char,
    pub len: usize,
}

#[repr(C)]
pub(crate) struct RorError {
    pub code: i32,
    pub _pad: i32,
    pub message: RorBuffer,
    pub detail: RorBuffer,
}

#[repr(C)]
pub(crate) struct RorRunRequest {
    pub rootfs: *const c_char,
    pub cwd: *const c_char,
    pub hostname: *const c_char,
    pub state_root: *const c_char,
    pub argv: *const *const c_char,
    pub env: *const *const c_char,
    pub stdio_fn: RorStdioFn,
    pub stdio_user: *mut c_void,
    pub argv_count: usize,
    pub env_count: usize,
    pub isolate_network: i32,
    pub _pad: i32,
}

impl RorBuffer {
    pub(crate) fn zero() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
        }
    }
}

impl RorError {
    pub(crate) fn zero() -> Self {
        Self {
            code: 0,
            _pad: 0,
            message: RorBuffer::zero(),
            detail: RorBuffer::zero(),
        }
    }
}

unsafe extern "C" {
    pub(crate) fn ror_startup(err: *mut RorError) -> i32;
    pub(crate) fn ror_run(
        req: *const RorRunRequest,
        exit_code: *mut i32,
        err: *mut RorError,
    ) -> i32;
    pub(crate) fn ror_diagnose(out: *mut RorBuffer, err: *mut RorError) -> i32;
    pub(crate) fn ror_buffer_free(buf: *mut RorBuffer);
    pub(crate) fn ror_error_free(err: *mut RorError);
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
        assert_eq!(size_of::<RorBuffer>(), ROR_BUFFER_SIZE);
        assert_eq!(align_of::<RorBuffer>(), ROR_BUFFER_ALIGN);
        assert_eq!(offset_of!(RorBuffer, data), ROR_BUFFER_OFF_DATA);
        assert_eq!(offset_of!(RorBuffer, len), ROR_BUFFER_OFF_LEN);

        assert_eq!(size_of::<RorError>(), ROR_ERROR_SIZE);
        assert_eq!(align_of::<RorError>(), ROR_ERROR_ALIGN);

        assert_eq!(size_of::<RorRunRequest>(), ROR_RUN_REQUEST_SIZE);
        assert_eq!(align_of::<RorRunRequest>(), ROR_RUN_REQUEST_ALIGN);
        assert_eq!(offset_of!(RorRunRequest, rootfs), ROR_RUN_OFF_ROOTFS);
        assert_eq!(offset_of!(RorRunRequest, stdio_fn), ROR_RUN_OFF_STDIO_FN);
        assert_eq!(
            offset_of!(RorRunRequest, isolate_network),
            ROR_RUN_OFF_ISOLATE_NETWORK
        );
    }
}
