// SPDX-License-Identifier: Apache-2.0

//! Raw C ABI. Types match `shim/include/rob_abi.h` on LP64.

#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::ffi::{c_char, c_void};

pub(crate) type RobLogFn =
    Option<unsafe extern "C" fn(user: *mut c_void, level: i32, data: *const c_char, len: usize)>;

#[repr(C)]
pub(crate) struct RobBuffer {
    pub data: *mut c_char,
    pub len: usize,
}

#[repr(C)]
pub(crate) struct RobError {
    pub code: i32,
    pub _pad: i32,
    pub message: RobBuffer,
    pub detail: RobBuffer,
}

#[repr(C)]
pub(crate) struct RobResult {
    pub image_id: RobBuffer,
    pub digest: RobBuffer,
    pub reference: RobBuffer,
}

#[repr(C)]
pub(crate) struct RobConfig {
    pub storage_root: *const c_char,
    pub run_root: *const c_char,
    pub storage_driver: *const c_char,
    pub registries_conf: *const c_char,
    pub signature_policy: *const c_char,
    pub auth_file: *const c_char,
    pub log_level: *const c_char,
    pub storage_opts: *const *const c_char,
    pub storage_opt_count: usize,
    pub insecure: i32,
    pub _pad: i32,
}

#[repr(C)]
pub(crate) struct RobBuildRequest {
    pub dockerfile: *const c_char,
    pub context_dir: *const c_char,
    pub tag: *const c_char,
    pub target: *const c_char,
    pub isolation: *const c_char,
    pub format: *const c_char,
    pub pull: *const c_char,
    pub os_name: *const c_char,
    pub arch: *const c_char,
    pub variant: *const c_char,
    pub build_arg_keys: *const *const c_char,
    pub build_arg_vals: *const *const c_char,
    pub labels: *const *const c_char,
    pub log_fn: RobLogFn,
    pub log_user: *mut c_void,
    pub build_arg_count: usize,
    pub label_count: usize,
    pub cancel_token: u64,
    pub layers: i32,
    pub no_cache: i32,
    pub squash: i32,
    pub quiet: i32,
}

#[repr(C)]
pub(crate) struct RobPushRequest {
    pub image: *const c_char,
    pub destination: *const c_char,
    pub username: *const c_char,
    pub password: *const c_char,
    pub format: *const c_char,
    pub log_fn: RobLogFn,
    pub log_user: *mut c_void,
    pub cancel_token: u64,
    pub insecure: i32,
    pub _pad: i32,
}

impl RobBuffer {
    pub(crate) fn zero() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
        }
    }
}

impl RobError {
    pub(crate) fn zero() -> Self {
        Self {
            code: 0,
            _pad: 0,
            message: RobBuffer::zero(),
            detail: RobBuffer::zero(),
        }
    }
}

impl RobResult {
    pub(crate) fn zero() -> Self {
        Self {
            image_id: RobBuffer::zero(),
            digest: RobBuffer::zero(),
            reference: RobBuffer::zero(),
        }
    }
}

unsafe extern "C" {
    pub(crate) fn rob_startup(err: *mut RobError) -> i32;
    pub(crate) fn rob_init(cfg: *const RobConfig, err: *mut RobError) -> i32;
    pub(crate) fn rob_shutdown(err: *mut RobError) -> i32;
    pub(crate) fn rob_build(
        req: *const RobBuildRequest,
        out: *mut RobResult,
        err: *mut RobError,
    ) -> i32;
    pub(crate) fn rob_tag(image: *const c_char, new_name: *const c_char, err: *mut RobError)
    -> i32;
    pub(crate) fn rob_push(
        req: *const RobPushRequest,
        out: *mut RobResult,
        err: *mut RobError,
    ) -> i32;
    pub(crate) fn rob_diagnose(out: *mut RobBuffer, err: *mut RobError) -> i32;
    pub(crate) fn rob_cancel_new() -> u64;
    pub(crate) fn rob_cancel(token: u64);
    pub(crate) fn rob_cancel_free(token: u64);
    pub(crate) fn rob_buffer_free(buf: *mut RobBuffer);
    pub(crate) fn rob_error_free(err: *mut RobError);
    pub(crate) fn rob_result_free(res: *mut RobResult);
    pub(crate) fn rob_buildah_version() -> *const c_char;
}

#[cfg(test)]
mod abi_constants {
    include!(concat!(env!("OUT_DIR"), "/abi_gen.rs"));
}

#[cfg(test)]
mod tests {
    use super::abi_constants::*;
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn layout_matches_c_header() {
        assert_eq!(size_of::<RobBuffer>(), ROB_BUFFER_SIZE);
        assert_eq!(align_of::<RobBuffer>(), ROB_BUFFER_ALIGN);
        assert_eq!(offset_of!(RobBuffer, data), ROB_BUFFER_OFF_DATA);
        assert_eq!(offset_of!(RobBuffer, len), ROB_BUFFER_OFF_LEN);

        assert_eq!(size_of::<RobError>(), ROB_ERROR_SIZE);
        assert_eq!(align_of::<RobError>(), ROB_ERROR_ALIGN);
        assert_eq!(offset_of!(RobError, code), ROB_ERROR_OFF_CODE);
        assert_eq!(offset_of!(RobError, message), ROB_ERROR_OFF_MESSAGE);
        assert_eq!(offset_of!(RobError, detail), ROB_ERROR_OFF_DETAIL);

        assert_eq!(size_of::<RobResult>(), ROB_RESULT_SIZE);
        assert_eq!(align_of::<RobResult>(), ROB_RESULT_ALIGN);
        assert_eq!(offset_of!(RobResult, image_id), ROB_RESULT_OFF_IMAGE_ID);
        assert_eq!(offset_of!(RobResult, digest), ROB_RESULT_OFF_DIGEST);
        assert_eq!(offset_of!(RobResult, reference), ROB_RESULT_OFF_REFERENCE);

        assert_eq!(size_of::<RobConfig>(), ROB_CONFIG_SIZE);
        assert_eq!(align_of::<RobConfig>(), ROB_CONFIG_ALIGN);
        assert_eq!(
            offset_of!(RobConfig, storage_root),
            ROB_CONFIG_OFF_STORAGE_ROOT
        );
        assert_eq!(offset_of!(RobConfig, run_root), ROB_CONFIG_OFF_RUN_ROOT);
        assert_eq!(
            offset_of!(RobConfig, storage_driver),
            ROB_CONFIG_OFF_STORAGE_DRIVER
        );
        assert_eq!(
            offset_of!(RobConfig, registries_conf),
            ROB_CONFIG_OFF_REGISTRIES_CONF
        );
        assert_eq!(
            offset_of!(RobConfig, signature_policy),
            ROB_CONFIG_OFF_SIGNATURE_POLICY
        );
        assert_eq!(offset_of!(RobConfig, auth_file), ROB_CONFIG_OFF_AUTH_FILE);
        assert_eq!(offset_of!(RobConfig, log_level), ROB_CONFIG_OFF_LOG_LEVEL);
        assert_eq!(
            offset_of!(RobConfig, storage_opts),
            ROB_CONFIG_OFF_STORAGE_OPTS
        );
        assert_eq!(
            offset_of!(RobConfig, storage_opt_count),
            ROB_CONFIG_OFF_STORAGE_OPT_COUNT
        );
        assert_eq!(offset_of!(RobConfig, insecure), ROB_CONFIG_OFF_INSECURE);

        assert_eq!(size_of::<RobBuildRequest>(), ROB_BUILD_REQUEST_SIZE);
        assert_eq!(align_of::<RobBuildRequest>(), ROB_BUILD_REQUEST_ALIGN);
        assert_eq!(
            offset_of!(RobBuildRequest, dockerfile),
            ROB_BUILD_OFF_DOCKERFILE
        );
        assert_eq!(
            offset_of!(RobBuildRequest, context_dir),
            ROB_BUILD_OFF_CONTEXT_DIR
        );
        assert_eq!(offset_of!(RobBuildRequest, tag), ROB_BUILD_OFF_TAG);
        assert_eq!(offset_of!(RobBuildRequest, target), ROB_BUILD_OFF_TARGET);
        assert_eq!(
            offset_of!(RobBuildRequest, isolation),
            ROB_BUILD_OFF_ISOLATION
        );
        assert_eq!(offset_of!(RobBuildRequest, format), ROB_BUILD_OFF_FORMAT);
        assert_eq!(offset_of!(RobBuildRequest, pull), ROB_BUILD_OFF_PULL);
        assert_eq!(offset_of!(RobBuildRequest, os_name), ROB_BUILD_OFF_OS_NAME);
        assert_eq!(offset_of!(RobBuildRequest, arch), ROB_BUILD_OFF_ARCH);
        assert_eq!(offset_of!(RobBuildRequest, variant), ROB_BUILD_OFF_VARIANT);
        assert_eq!(
            offset_of!(RobBuildRequest, build_arg_keys),
            ROB_BUILD_OFF_BUILD_ARG_KEYS
        );
        assert_eq!(
            offset_of!(RobBuildRequest, build_arg_vals),
            ROB_BUILD_OFF_BUILD_ARG_VALS
        );
        assert_eq!(offset_of!(RobBuildRequest, labels), ROB_BUILD_OFF_LABELS);
        assert_eq!(offset_of!(RobBuildRequest, log_fn), ROB_BUILD_OFF_LOG_FN);
        assert_eq!(
            offset_of!(RobBuildRequest, log_user),
            ROB_BUILD_OFF_LOG_USER
        );
        assert_eq!(
            offset_of!(RobBuildRequest, build_arg_count),
            ROB_BUILD_OFF_BUILD_ARG_COUNT
        );
        assert_eq!(
            offset_of!(RobBuildRequest, label_count),
            ROB_BUILD_OFF_LABEL_COUNT
        );
        assert_eq!(
            offset_of!(RobBuildRequest, cancel_token),
            ROB_BUILD_OFF_CANCEL_TOKEN
        );
        assert_eq!(offset_of!(RobBuildRequest, layers), ROB_BUILD_OFF_LAYERS);
        assert_eq!(
            offset_of!(RobBuildRequest, no_cache),
            ROB_BUILD_OFF_NO_CACHE
        );
        assert_eq!(offset_of!(RobBuildRequest, squash), ROB_BUILD_OFF_SQUASH);
        assert_eq!(offset_of!(RobBuildRequest, quiet), ROB_BUILD_OFF_QUIET);

        assert_eq!(size_of::<RobPushRequest>(), ROB_PUSH_REQUEST_SIZE);
        assert_eq!(align_of::<RobPushRequest>(), ROB_PUSH_REQUEST_ALIGN);
        assert_eq!(offset_of!(RobPushRequest, image), ROB_PUSH_OFF_IMAGE);
        assert_eq!(
            offset_of!(RobPushRequest, destination),
            ROB_PUSH_OFF_DESTINATION
        );
        assert_eq!(offset_of!(RobPushRequest, username), ROB_PUSH_OFF_USERNAME);
        assert_eq!(offset_of!(RobPushRequest, password), ROB_PUSH_OFF_PASSWORD);
        assert_eq!(offset_of!(RobPushRequest, format), ROB_PUSH_OFF_FORMAT);
        assert_eq!(offset_of!(RobPushRequest, log_fn), ROB_PUSH_OFF_LOG_FN);
        assert_eq!(offset_of!(RobPushRequest, log_user), ROB_PUSH_OFF_LOG_USER);
        assert_eq!(
            offset_of!(RobPushRequest, cancel_token),
            ROB_PUSH_OFF_CANCEL_TOKEN
        );
        assert_eq!(offset_of!(RobPushRequest, insecure), ROB_PUSH_OFF_INSECURE);
    }
}
