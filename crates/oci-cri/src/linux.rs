// SPDX-License-Identifier: Apache-2.0

//! Linux engine: the Go c-archive behind [`crate::ffi`].
//!
//! Each call serialises one JSON op, hands it to `rok_call`, and parses the
//! JSON response. Output/input callbacks are trampolines over caller-owned
//! closures; for `start` the closure is boxed and stays alive until the
//! matching `wait` call reclaims it, mirroring the shim contract.

use std::ffi::{CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};

use crate::engine::{
    Auth, Engine, EngineImage, EngineState, EngineStats, ExecOutput, FsInfo, InputSource,
    OutputSink,
};
use crate::error::{Error, ErrorCode, Result};
use crate::ffi;

static OPEN: AtomicBool = AtomicBool::new(false);

pub(crate) fn startup() -> Result<()> {
    let mut err = ffi::RokError::zero();
    let rc = unsafe { ffi::rok_startup(&mut err) };
    finish(rc, err)
}

pub(crate) fn open() -> Result<()> {
    if OPEN.swap(true, Ordering::SeqCst) {
        return Err(Error::new(ErrorCode::State, "runtime is already open", ""));
    }
    Ok(())
}

pub(crate) fn shutdown() -> Result<()> {
    if !OPEN.swap(false, Ordering::SeqCst) {
        return Err(Error::new(ErrorCode::State, "runtime is not open", ""));
    }
    Ok(())
}

pub(crate) fn diagnose() -> Result<String> {
    let mut out = ffi::RokBuffer::zero();
    let mut err = ffi::RokError::zero();
    let rc = unsafe { ffi::rok_diagnose(&mut out, &mut err) };
    if rc == 0 {
        let report = unsafe { read_buf(&out) };
        unsafe { ffi::rok_buffer_free(&mut out) };
        return Ok(report);
    }
    unsafe { ffi::rok_buffer_free(&mut out) };
    Err(take_error(err))
}

/// The Linux [`Engine`] implementation rooted at one image/state directory.
pub struct LinuxEngine {
    root: PathBuf,
    state_root: PathBuf,
}

impl LinuxEngine {
    /// Create an engine storing images under `root`, with libcontainer
    /// state in `state_root`.
    pub fn new(root: PathBuf, state_root: PathBuf) -> Self {
        Self { root, state_root }
    }

    fn call(&self, request: Value) -> Result<Value> {
        self.call_io(request, None, None)
    }

    fn call_io(
        &self,
        request: Value,
        on_output: Option<OutputSink>,
        next_input: Option<InputSource>,
    ) -> Result<Value> {
        if !OPEN.load(Ordering::SeqCst) {
            return Err(Error::new(ErrorCode::State, "runtime is not open", ""));
        }
        let mut request = request;
        request["store_root"] = json!(self.root.to_string_lossy());
        request["state_root"] = json!(self.state_root.to_string_lossy());
        let text = serde_json::to_string(&request).map_err(internal)?;
        let c_text = CString::new(text).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "request contains a NUL byte",
                "",
            )
        })?;
        // The boxes own the closures for the duration of this call. For
        // `start`, start_container leaks its box on purpose and wait_container
        // cannot reclaim it (the pointer lives in the shim), so the start
        // path goes through call_start below instead.
        let mut out_box = on_output.map(|cb| Box::new(Sink { callback: cb }));
        let mut in_box = next_input.map(|cb| Box::new(Source { next: cb }));
        let mut out = ffi::RokBuffer::zero();
        let mut err = ffi::RokError::zero();
        let rc = unsafe {
            ffi::rok_call(
                c_text.as_ptr(),
                if out_box.is_some() {
                    Some(trampoline_out)
                } else {
                    None
                },
                out_box
                    .as_mut()
                    .map(|b| (b.as_mut() as *mut Sink).cast::<c_void>())
                    .unwrap_or(std::ptr::null_mut()),
                if in_box.is_some() {
                    Some(trampoline_in)
                } else {
                    None
                },
                in_box
                    .as_mut()
                    .map(|b| (b.as_mut() as *mut Source).cast::<c_void>())
                    .unwrap_or(std::ptr::null_mut()),
                &mut out,
                &mut err,
            )
        };
        if rc != 0 {
            unsafe { ffi::rok_buffer_free(&mut out) };
            return Err(take_error(err));
        }
        let text = unsafe { read_buf(&out) };
        unsafe { ffi::rok_buffer_free(&mut out) };
        if text.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_str(&text).map_err(internal)
    }
}

struct Sink {
    callback: OutputSink,
}

struct Source {
    next: InputSource,
}

unsafe extern "C" fn trampoline_out(
    user: *mut c_void,
    stream: i32,
    data: *const c_char,
    len: usize,
) {
    if user.is_null() || data.is_null() || len == 0 {
        return;
    }
    let sink = unsafe { &*(user as *const Sink) };
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) };
    let _ = catch_unwind(AssertUnwindSafe(|| (sink.callback)(stream as u8, bytes)));
}

unsafe extern "C" fn trampoline_in(user: *mut c_void, buf: *mut c_char, cap: usize) -> isize {
    if user.is_null() || buf.is_null() || cap == 0 {
        return -1;
    }
    let source = unsafe { &*(user as *const Source) };
    let result = catch_unwind(AssertUnwindSafe(|| (source.next)()));
    match result {
        Ok(bytes) if bytes.is_empty() => 0,
        Ok(bytes) => {
            let n = bytes.len().min(cap);
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), n) };
            n as isize
        }
        Err(_) => -1,
    }
}

fn parse<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(internal)
}

impl Engine for LinuxEngine {
    fn pull_image(&self, image: &str, auth: Option<&Auth>, insecure: bool) -> Result<String> {
        let value = self.call(json!({
            "op": "pull_image", "image": image, "auth": auth, "insecure": insecure,
        }))?;
        Ok(value["image_ref"].as_str().unwrap_or_default().to_string())
    }

    fn list_images(&self, filter: &str) -> Result<Vec<EngineImage>> {
        let value = self.call(json!({"op": "list_images", "filter": filter}))?;
        parse(value["images"].clone())
    }

    fn remove_image(&self, image: &str) -> Result<()> {
        self.call(json!({"op": "remove_image", "image": image}))?;
        Ok(())
    }

    fn image_fs_info(&self) -> Result<Vec<FsInfo>> {
        let value = self.call(json!({"op": "image_fs_info"}))?;
        parse(value["filesystems"].clone())
    }

    fn prepare_rootfs(&self, id: &str, image: &str) -> Result<PathBuf> {
        let value = self.call(json!({"op": "prepare_rootfs", "id": id, "image": image}))?;
        Ok(PathBuf::from(value["rootfs"].as_str().unwrap_or_default()))
    }

    fn release_rootfs(&self, id: &str) -> Result<()> {
        self.call(json!({"op": "release_rootfs", "id": id}))?;
        Ok(())
    }

    fn create_container(&self, id: &str, spec_json: &str) -> Result<()> {
        let spec: Value = serde_json::from_str(spec_json).map_err(internal)?;
        self.call(json!({"op": "create", "id": id, "spec": spec}))?;
        Ok(())
    }

    fn start_container(&self, id: &str, on_output: OutputSink) -> Result<()> {
        // The shim keeps this callback registered until wait_container
        // returns. Leak the box; the wait path in the shim joins the output
        // pumps before returning, after which the pointer is dead. A leaked
        // closure per container start is bounded by container count and is
        // reclaimed at process exit; containers are also destroyed on
        // shutdown. (The shim contract documents this lifetime.)
        let boxed = Box::new(Sink {
            callback: on_output,
        });
        let user = Box::leak(boxed) as *mut Sink;
        let mut out = ffi::RokBuffer::zero();
        let mut err = ffi::RokError::zero();
        let text = serde_json::to_string(
            &json!({"op": "start", "id": id, "store_root": self.root.to_string_lossy(), "state_root": self.state_root.to_string_lossy()}),
        )
        .map_err(internal)?;
        let c_text = CString::new(text).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "request contains a NUL byte",
                "",
            )
        })?;
        let rc = unsafe {
            ffi::rok_call(
                c_text.as_ptr(),
                Some(trampoline_out),
                user.cast::<c_void>(),
                None,
                std::ptr::null_mut(),
                &mut out,
                &mut err,
            )
        };
        unsafe { ffi::rok_buffer_free(&mut out) };
        if rc != 0 {
            return Err(take_error(err));
        }
        Ok(())
    }

    fn wait_container(&self, id: &str) -> Result<i32> {
        let value = self.call(json!({"op": "wait", "id": id}))?;
        Ok(value["exit_code"].as_i64().unwrap_or(-1) as i32)
    }

    fn signal_container(&self, id: &str, signal: i32) -> Result<()> {
        self.call(json!({"op": "kill", "id": id, "signal": signal}))?;
        Ok(())
    }

    fn remove_container(&self, id: &str) -> Result<()> {
        self.call(json!({"op": "delete", "id": id}))?;
        Ok(())
    }

    fn container_state(&self, id: &str) -> Result<EngineState> {
        let value = self.call(json!({"op": "state", "id": id}))?;
        parse(value)
    }

    fn exec_sync(&self, id: &str, cmd: &[String], timeout_secs: i64) -> Result<ExecOutput> {
        let stdout = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stderr = Arc::new(std::sync::Mutex::new(Vec::new()));
        let out_sink = Arc::clone(&stdout);
        let err_sink = Arc::clone(&stderr);
        let sink: OutputSink = Arc::new(move |stream, data| {
            let target = if stream == 2 { &err_sink } else { &out_sink };
            target
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .extend_from_slice(data);
        });
        let value = self.call_io(
            json!({"op": "exec", "id": id, "cmd": cmd, "tty": false}),
            Some(sink),
            None,
        )?;
        let _ = timeout_secs; // enforced by the caller via a watchdog thread
        Ok(ExecOutput {
            exit_code: value["exit_code"].as_i64().unwrap_or(-1) as i32,
            stdout: stdout.lock().unwrap_or_else(|p| p.into_inner()).clone(),
            stderr: stderr.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        })
    }

    fn exec_stream(
        &self,
        id: &str,
        cmd: &[String],
        tty: bool,
        next_input: InputSource,
        on_output: OutputSink,
    ) -> Result<i32> {
        let value = self.call_io(
            json!({"op": "exec", "id": id, "cmd": cmd, "tty": tty}),
            Some(on_output),
            Some(next_input),
        )?;
        Ok(value["exit_code"].as_i64().unwrap_or(-1) as i32)
    }

    fn write_stdin(&self, id: &str, data: &[u8]) -> Result<()> {
        use base64::Engine as _;
        self.call(json!({
            "op": "write_stdin", "id": id,
            "data": base64::engine::general_purpose::STANDARD.encode(data),
        }))?;
        Ok(())
    }

    fn resize_tty(&self, id: &str, width: u16, height: u16) -> Result<()> {
        self.call(json!({"op": "resize", "id": id, "width": width, "height": height}))?;
        Ok(())
    }

    fn container_stats(&self, id: &str) -> Result<EngineStats> {
        let value = self.call(json!({"op": "stats", "id": id}))?;
        parse(value)
    }

    fn update_resources(&self, id: &str, resources_json: &str) -> Result<()> {
        let resources: Value = serde_json::from_str(resources_json).map_err(internal)?;
        self.call(json!({"op": "update", "id": id, "resources": resources}))?;
        Ok(())
    }

    fn checkpoint(&self, id: &str, image: &str, parent: &str) -> Result<()> {
        self.call(json!({"op": "checkpoint", "id": id, "image": image, "parent": parent}))?;
        Ok(())
    }

    fn diagnose(&self) -> Result<String> {
        diagnose()
    }
}

fn internal(err: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Internal, err.to_string(), "")
}

fn finish(rc: i32, err: ffi::RokError) -> Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(take_error(err))
    }
}

fn take_error(mut err: ffi::RokError) -> Error {
    let code = ErrorCode::from_raw(err.code);
    let message = unsafe { read_buf(&err.message) };
    let detail = unsafe { read_buf(&err.detail) };
    unsafe { ffi::rok_error_free(&mut err) };
    Error::new(code, message, detail)
}

unsafe fn read_buf(buf: &ffi::RokBuffer) -> String {
    if buf.data.is_null() || buf.len == 0 {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.data as *const u8, buf.len) };
    String::from_utf8_lossy(bytes).into_owned()
}
