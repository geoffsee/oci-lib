// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::OutputFn;
use crate::error::{Error, ErrorCode};
use crate::ffi;
use crate::request::PreparedRun;

static OPEN: AtomicBool = AtomicBool::new(false);

struct Sink {
    callback: OutputFn,
}

pub(crate) fn startup() -> Result<(), Error> {
    let mut err = ffi::RorError::zero();
    let rc = unsafe { ffi::ror_startup(&mut err) };
    finish(rc, err)
}

pub(crate) fn open() -> Result<(), Error> {
    if OPEN.swap(true, Ordering::SeqCst) {
        return Err(Error::new(ErrorCode::State, "runtime is already open", ""));
    }
    Ok(())
}

pub(crate) fn shutdown() -> Result<(), Error> {
    if !OPEN.swap(false, Ordering::SeqCst) {
        return Err(Error::new(ErrorCode::State, "runtime is not open", ""));
    }
    Ok(())
}

pub(crate) fn diagnose() -> Result<String, Error> {
    let mut out = ffi::RorBuffer::zero();
    let mut err = ffi::RorError::zero();
    let rc = unsafe { ffi::ror_diagnose(&mut out, &mut err) };
    if rc == 0 {
        let report = unsafe { read_buf(&out) };
        unsafe { ffi::ror_buffer_free(&mut out) };
        return Ok(report);
    }
    unsafe { ffi::ror_buffer_free(&mut out) };
    Err(take_error(err))
}

pub(crate) fn run(prepared: &PreparedRun, on_output: Option<OutputFn>) -> Result<i32, Error> {
    if !OPEN.load(Ordering::SeqCst) {
        return Err(Error::new(ErrorCode::State, "runtime is not open", ""));
    }
    let rootfs = c_string(prepared.rootfs.to_str().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("rootfs is not valid Unicode: {}", prepared.rootfs.display()),
            "",
        )
    })?)?;
    let cwd = c_string(&prepared.cwd)?;
    let hostname = c_string(&prepared.hostname)?;
    let state_root = match &prepared.state_root {
        Some(path) => c_string(path_str(path)?)?,
        None => c_string("")?,
    };
    let argv = c_list(&prepared.argv)?;
    let env = c_list(&prepared.env)?;
    let argv_ptrs: Vec<*const c_char> = argv.iter().map(|item| item.as_ptr()).collect();
    let env_ptrs: Vec<*const c_char> = env.iter().map(|item| item.as_ptr()).collect();
    let sink = on_output.map(|callback| Sink { callback });
    let mut request = ffi::RorRunRequest {
        rootfs: rootfs.as_ptr(),
        cwd: cwd.as_ptr(),
        hostname: hostname.as_ptr(),
        state_root: state_root.as_ptr(),
        argv: if argv_ptrs.is_empty() {
            std::ptr::null()
        } else {
            argv_ptrs.as_ptr()
        },
        env: if env_ptrs.is_empty() {
            std::ptr::null()
        } else {
            env_ptrs.as_ptr()
        },
        stdio_fn: if sink.is_some() {
            Some(trampoline)
        } else {
            None
        },
        stdio_user: sink
            .as_ref()
            .map(|item| item as *const Sink as *mut c_void)
            .unwrap_or(std::ptr::null_mut()),
        argv_count: argv_ptrs.len(),
        env_count: env_ptrs.len(),
        isolate_network: i32::from(prepared.isolate_network),
        _pad: 0,
    };
    let mut exit_code = 0;
    let mut err = ffi::RorError::zero();
    let rc = unsafe { ffi::ror_run(&mut request, &mut exit_code, &mut err) };
    if rc == 0 {
        return Ok(exit_code);
    }
    Err(take_error(err))
}

unsafe extern "C" fn trampoline(user: *mut c_void, stream: i32, data: *const c_char, len: usize) {
    if user.is_null() || data.is_null() || len == 0 {
        return;
    }
    let sink = unsafe { &*(user as *const Sink) };
    let bytes = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
    let _ = catch_unwind(AssertUnwindSafe(|| (sink.callback)(stream as u8, bytes)));
}

fn c_list(values: &[String]) -> Result<Vec<CString>, Error> {
    values.iter().map(|value| c_string(value)).collect()
}

fn c_string(value: &str) -> Result<CString, Error> {
    CString::new(value)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "string contains a NUL byte", ""))
}

fn path_str(path: &Path) -> Result<&str, Error> {
    path.to_str().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("path is not valid Unicode: {}", path.display()),
            "",
        )
    })
}

fn finish(rc: i32, err: ffi::RorError) -> Result<(), Error> {
    if rc == 0 {
        Ok(())
    } else {
        Err(take_error(err))
    }
}

fn take_error(mut err: ffi::RorError) -> Error {
    let code = ErrorCode::from_raw(err.code);
    let message = unsafe { read_buf(&err.message) };
    let detail = unsafe { read_buf(&err.detail) };
    unsafe { ffi::ror_error_free(&mut err) };
    Error::new(code, message, detail)
}

unsafe fn read_buf(buf: &ffi::RorBuffer) -> String {
    if buf.data.is_null() || buf.len == 0 {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.data as *const u8, buf.len) };
    String::from_utf8_lossy(bytes).into_owned()
}
