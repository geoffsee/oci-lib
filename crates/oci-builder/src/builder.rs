// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::config::{Config, ImageFormat, Isolation, PullPolicy, StorageDriver};
use crate::error::{Error, ErrorCode, Result, read_buf};
#[cfg_attr(target_os = "macos", allow(unused_imports))]
use crate::ffi::{
    self, RobBuffer, RobBuildRequest, RobConfig, RobError, RobPushRequest, RobResult,
};

static OP: Mutex<()> = Mutex::new(());

/// A line from the engine. Bytes are copied before the log callback returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// The stream type that produced this log entry.
    pub stream: LogStream,
    /// The raw log message text received from the engine.
    pub message: String,
}

/// Which stream produced a [`LogRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    /// Step progress and image layer download/extract progress.
    Progress,
    /// General informational message from Buildah.
    Info,
    /// Warning message for non-fatal issues.
    Warn,
    /// Error message from an instruction or subsystem.
    Error,
}

impl LogStream {
    fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Progress,
            2 => Self::Warn,
            3 => Self::Error,
            _ => Self::Info,
        }
    }
}

/// Image identity returned by a build, tag is not included here, or a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    /// Unique local identifier (hash) of the image.
    pub image_id: String,
    /// Manifest digest, when the engine produced one.
    pub digest: Option<String>,
    /// Canonical reference, or the tag / destination that was requested.
    pub reference: Option<String>,
}

/// Cancels one in-flight build or push.
///
/// Clone shares the same token. The last drop frees it and does not cancel.
/// The token must still be alive when the operation starts; a token that was
/// already freed is reported as cancelled. `cancel` does not take the engine
/// lock, so it can run while `build` or `push` is blocked in the shim.
///
/// Dropping the token from another thread during the call is safe only if a
/// clone is retained by the request for the duration of the call.
#[derive(Clone, Debug)]
pub struct CancelToken {
    inner: Arc<CancelInner>,
}

#[derive(Debug)]
struct CancelInner {
    id: u64,
}

impl CancelToken {
    /// Create a new cancellation token.
    pub fn new() -> Result<Self> {
        let id = unsafe { ffi::rob_cancel_new() };
        if id == 0 {
            return Err(Error::new(
                ErrorCode::Internal,
                "cancel token allocator returned 0",
                "",
            ));
        }
        Ok(Self {
            inner: Arc::new(CancelInner { id }),
        })
    }

    /// Signal cancellation to any build or push using this token.
    pub fn cancel(&self) {
        #[cfg(target_os = "macos")]
        crate::macos::cancel(self.inner.id);
        #[cfg(not(target_os = "macos"))]
        unsafe {
            ffi::rob_cancel(self.inner.id)
        }
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn raw_id(&self) -> u64 {
        self.inner.id
    }
}

impl Drop for CancelInner {
    fn drop(&mut self) {
        unsafe { ffi::rob_cancel_free(self.id) }
    }
}

/// Build one Dockerfile or Containerfile.
///
/// The callback must not call back into [`Builder`]. Doing so deadlocks on the
/// process-wide engine lock. It may run on a Go thread.
#[derive(Clone)]
pub struct BuildRequest {
    /// Path to the Dockerfile or Containerfile to build.
    pub dockerfile: PathBuf,
    /// Root directory for the build context (used for `COPY` and `ADD`).
    pub context_dir: PathBuf,
    /// Optional name/tag to apply to the built image upon success.
    pub tag: Option<String>,
    /// Target stage for multi-stage Dockerfiles.
    pub target: Option<String>,
    /// Isolation mechanism used for `RUN` instructions.
    pub isolation: Isolation,
    /// Output image manifest format (OCI or Docker schema 2).
    pub format: ImageFormat,
    /// Policy determining when to pull base images from a remote registry.
    pub pull: PullPolicy,
    /// Target operating system for the output image.
    pub os: Option<String>,
    /// Target CPU architecture for the output image.
    pub arch: Option<String>,
    /// Target CPU architecture variant.
    pub variant: Option<String>,
    /// Build arguments passed to the build engine (`ARG` instructions).
    pub build_args: BTreeMap<String, String>,
    /// Metadata key-value pairs applied to the output image (`LABEL` instructions).
    pub labels: BTreeMap<String, String>,
    /// Commit one layer per instruction. The default is on.
    pub layers: bool,
    /// Ignore cached layers and rebuild all instructions.
    pub no_cache: bool,
    /// Squash all resulting image layers into a single layer.
    pub squash: bool,
    /// Suppress verbose progress output during the build.
    pub quiet: bool,
    /// Optional cancellation token to stop the build in-flight.
    pub cancel: Option<CancelToken>,
    /// Optional callback invoked for each line of progress and log output.
    pub on_log: Option<Arc<dyn Fn(LogRecord) + Send + Sync>>,
}

impl Default for BuildRequest {
    fn default() -> Self {
        Self {
            dockerfile: PathBuf::new(),
            context_dir: PathBuf::new(),
            tag: None,
            target: None,
            isolation: Isolation::Default,
            format: ImageFormat::Oci,
            pull: PullPolicy::IfMissing,
            os: None,
            arch: None,
            variant: None,
            build_args: BTreeMap::new(),
            labels: BTreeMap::new(),
            layers: true,
            no_cache: false,
            squash: false,
            quiet: false,
            cancel: None,
            on_log: None,
        }
    }
}

impl std::fmt::Debug for BuildRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildRequest")
            .field("dockerfile", &self.dockerfile)
            .field("context_dir", &self.context_dir)
            .field("tag", &self.tag)
            .field("target", &self.target)
            .field("isolation", &self.isolation)
            .field("format", &self.format)
            .field("pull", &self.pull)
            .field("os", &self.os)
            .field("arch", &self.arch)
            .field("variant", &self.variant)
            .field("build_args", &self.build_args)
            .field("labels", &self.labels)
            .field("layers", &self.layers)
            .field("no_cache", &self.no_cache)
            .field("squash", &self.squash)
            .field("quiet", &self.quiet)
            .field("cancel", &self.cancel)
            .finish_non_exhaustive()
    }
}

impl BuildRequest {
    /// Create a new build request for a Dockerfile and context directory.
    pub fn new(dockerfile: impl Into<PathBuf>, context_dir: impl Into<PathBuf>) -> Self {
        Self {
            dockerfile: dockerfile.into(),
            context_dir: context_dir.into(),
            ..Self::default()
        }
    }

    /// Attach a logging callback to receive progress and engine log records.
    pub fn with_log<F>(mut self, callback: F) -> Self
    where
        F: Fn(LogRecord) + Send + Sync + 'static,
    {
        self.on_log = Some(Arc::new(callback));
        self
    }

    pub(crate) fn prepare(&self) -> Result<PreparedPaths> {
        let dockerfile = std::fs::canonicalize(&self.dockerfile).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("dockerfile {}: {err}", self.dockerfile.display()),
                "",
            )
        })?;
        if !dockerfile.is_file() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("dockerfile is not a file: {}", dockerfile.display()),
                "",
            ));
        }
        let context_dir = std::fs::canonicalize(&self.context_dir).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("context {}: {err}", self.context_dir.display()),
                "",
            )
        })?;
        if !context_dir.is_dir() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("context is not a directory: {}", context_dir.display()),
                "",
            ));
        }
        Ok(PreparedPaths {
            dockerfile,
            context_dir,
        })
    }
}

#[derive(Debug)]
pub(crate) struct PreparedPaths {
    pub(crate) dockerfile: PathBuf,
    pub(crate) context_dir: PathBuf,
}

/// Push one local image.
///
/// `password` is copied into the Go heap for the call and is not written to logs.
#[derive(Clone)]
pub struct PushRequest {
    /// Name or ID of the local image to push.
    pub image: String,
    /// Destination repository and tag reference in the remote registry.
    pub destination: String,
    /// Username for registry authentication.
    pub username: String,
    /// Password or token for registry authentication.
    pub password: String,
    /// `None` keeps the source manifest type.
    pub format: Option<ImageFormat>,
    /// Allow connecting to HTTP registries or skipping TLS verification.
    pub insecure: bool,
    /// Optional cancellation token to abort the push in-flight.
    pub cancel: Option<CancelToken>,
    /// Optional callback to receive streaming push log records.
    pub on_log: Option<Arc<dyn Fn(LogRecord) + Send + Sync>>,
}

impl PushRequest {
    /// Create a new push request for a local image and remote destination.
    pub fn new(image: impl Into<String>, destination: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            destination: destination.into(),
            username: String::new(),
            password: String::new(),
            format: None,
            insecure: false,
            cancel: None,
            on_log: None,
        }
    }

    /// Attach a logging callback to receive progress and push log records.
    pub fn with_log<F>(mut self, callback: F) -> Self
    where
        F: Fn(LogRecord) + Send + Sync + 'static,
    {
        self.on_log = Some(Arc::new(callback));
        self
    }
}

impl std::fmt::Debug for PushRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushRequest")
            .field("image", &self.image)
            .field("destination", &self.destination)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("format", &self.format)
            .field("insecure", &self.insecure)
            .field("cancel", &self.cancel)
            .finish_non_exhaustive()
    }
}

/// Handle for the process-wide Buildah store.
///
/// `Drop` does not shut the store down. Call [`Builder::shutdown`] so the
/// graph driver can release mounts. A second [`Builder::open`] fails until
/// shutdown has returned.
#[derive(Debug)]
pub struct Builder {
    _private: (),
}

impl Builder {
    /// Initialize and open the process-wide Buildah store with the given configuration.
    pub fn open(config: Config) -> Result<Self> {
        startup()?;
        #[cfg(target_os = "macos")]
        {
            crate::macos::open(config)?;
            Ok(Builder { _private: () })
        }
        #[cfg(not(target_os = "macos"))]
        let held = HeldConfig::from_config(&config)?;
        #[cfg(not(target_os = "macos"))]
        with_op(|| unsafe {
            let mut err = RobError::zero();
            let code = ffi::rob_init(&held.raw, &mut err);
            let result = take_status(code, &err);
            ffi::rob_error_free(&mut err);
            result.map(|()| Builder { _private: () })
        })
    }

    /// Build an OCI or Docker image according to the specified request.
    pub fn build(&self, request: BuildRequest) -> Result<ImageInfo> {
        let _ = self;
        let paths = request.prepare()?;
        #[cfg(target_os = "macos")]
        {
            crate::macos::build(&request, &paths)
        }
        #[cfg(not(target_os = "macos"))]
        with_op(|| execute_build(&request, &paths))
    }

    /// Add a new tag/name to an existing image in local storage.
    pub fn tag(&self, image: &str, new_name: &str) -> Result<()> {
        let _ = self;
        if image.is_empty() || new_name.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "image and new name are required",
                "",
            ));
        }
        #[cfg(target_os = "macos")]
        {
            crate::macos::tag(image, new_name)
        }
        #[cfg(not(target_os = "macos"))]
        let image = cstring(image.as_bytes())?;
        #[cfg(not(target_os = "macos"))]
        let new_name = cstring(new_name.as_bytes())?;
        #[cfg(not(target_os = "macos"))]
        with_op(|| unsafe {
            let mut err = RobError::zero();
            let code = ffi::rob_tag(image.as_ptr(), new_name.as_ptr(), &mut err);
            let result = take_status(code, &err);
            ffi::rob_error_free(&mut err);
            result
        })
    }

    /// Push an image from local storage to a remote registry.
    pub fn push(&self, request: PushRequest) -> Result<ImageInfo> {
        let _ = self;
        if request.image.is_empty() || request.destination.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "image and destination are required",
                "",
            ));
        }
        #[cfg(target_os = "macos")]
        {
            crate::macos::push(&request)
        }
        #[cfg(not(target_os = "macos"))]
        with_op(|| execute_push(&request))
    }

    /// Shut down the store and release graph driver mounts.
    pub fn shutdown(self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            crate::macos::shutdown()
        }
        #[cfg(not(target_os = "macos"))]
        with_op(|| unsafe {
            let mut err = RobError::zero();
            let code = ffi::rob_shutdown(&mut err);
            let result = take_status(code, &err);
            ffi::rob_error_free(&mut err);
            result
        })
    }

    /// Host prerequisites. `Err` means the report's status is `blocked`.
    /// Warnings are included in an `Ok` report.
    pub fn diagnose() -> Result<String> {
        startup()?;
        #[cfg(target_os = "macos")]
        {
            crate::macos::diagnose()
        }
        #[cfg(not(target_os = "macos"))]
        with_op(|| unsafe {
            let mut buf = RobBuffer::zero();
            let mut err = RobError::zero();
            let code = ffi::rob_diagnose(&mut buf, &mut err);
            let report = read_buf(&buf);
            let result = if code == 0 {
                Ok(report)
            } else {
                let mut error = Error::from_ffi(&err);
                if error.detail().is_empty() && !report.is_empty() {
                    error = Error::new(error.code(), error.message(), report);
                }
                Err(error)
            };
            ffi::rob_buffer_free(&mut buf);
            ffi::rob_error_free(&mut err);
            result
        })
    }
}

/// Prepare Buildah re-exec and, when required, enter a rootless user namespace.
///
/// Call this on the first line of `main`, before spawning threads and before
/// parsing arguments. Internal storage helpers re-exec this binary and dispatch
/// on `argv[0]` inside `startup`. A rootless build replaces this process: the
/// parent waits for the child and exits with the child's status, and the
/// child's `argv[0]` has a `-in-a-user-namespace` suffix.
///
/// On macOS this returns immediately. The Linux engine starts later, inside
/// the guest, on the first build, tag, or push. On other non-Linux builds
/// this returns [`ErrorCode::Unsupported`] and does not touch a Buildah engine.
pub fn startup() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    with_op(|| unsafe {
        let mut err = RobError::zero();
        let code = ffi::rob_startup(&mut err);
        let result = take_status(code, &err);
        ffi::rob_error_free(&mut err);
        result
    })
}

/// Buildah version linked into this binary, or `unsupported` on the stub.
pub fn buildah_version() -> String {
    unsafe {
        let ptr = ffi::rob_buildah_version();
        if ptr.is_null() {
            return String::new();
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

fn with_op<T>(body: impl FnOnce() -> T) -> T {
    let _guard = OP.lock().unwrap_or_else(|poison| poison.into_inner());
    body()
}

fn take_status(code: i32, err: &RobError) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::from_ffi(err))
    }
}

fn execute_build(request: &BuildRequest, paths: &PreparedPaths) -> Result<ImageInfo> {
    let dockerfile = cstring_path(&paths.dockerfile)?;
    let context_dir = cstring_path(&paths.context_dir)?;
    let tag = opt_cstring(request.tag.as_deref().unwrap_or(""))?;
    let target = opt_cstring(request.target.as_deref().unwrap_or(""))?;
    let isolation = opt_cstring(request.isolation.as_abi())?;
    let format = opt_cstring(request.format.as_abi())?;
    let pull = opt_cstring(request.pull.as_abi())?;
    let os_name = opt_cstring(request.os.as_deref().unwrap_or(""))?;
    let arch = opt_cstring(request.arch.as_deref().unwrap_or(""))?;
    let variant = opt_cstring(request.variant.as_deref().unwrap_or(""))?;
    let arg_keys = CStringList::from_strings(request.build_args.keys().map(String::as_str))?;
    let arg_vals = CStringList::from_strings(request.build_args.values().map(String::as_str))?;
    let labels = CStringList::from_strings(request.labels.iter().map(|(k, v)| format!("{k}={v}")))?;
    let slot = request
        .on_log
        .clone()
        .map(|callback| LogTarget { callback });
    let log_user = slot
        .as_ref()
        .map(|target| target as *const LogTarget as *mut c_void)
        .unwrap_or(std::ptr::null_mut());
    let raw = RobBuildRequest {
        dockerfile: dockerfile.as_ptr(),
        context_dir: context_dir.as_ptr(),
        tag: tag.as_ptr(),
        target: target.as_ptr(),
        isolation: isolation.as_ptr(),
        format: format.as_ptr(),
        pull: pull.as_ptr(),
        os_name: os_name.as_ptr(),
        arch: arch.as_ptr(),
        variant: variant.as_ptr(),
        build_arg_keys: arg_keys.as_ptr(),
        build_arg_vals: arg_vals.as_ptr(),
        labels: labels.as_ptr(),
        log_fn: if slot.is_some() {
            Some(log_trampoline)
        } else {
            None
        },
        log_user,
        build_arg_count: arg_keys.len(),
        label_count: labels.len(),
        cancel_token: token_id(&request.cancel),
        layers: i32::from(request.layers),
        no_cache: i32::from(request.no_cache),
        squash: i32::from(request.squash),
        quiet: i32::from(request.quiet),
    };
    unsafe {
        let mut out = RobResult::zero();
        let mut err = RobError::zero();
        let code = ffi::rob_build(&raw, &mut out, &mut err);
        let result = match take_status(code, &err) {
            Ok(()) => Ok(take_info(&out)),
            Err(error) => Err(error),
        };
        ffi::rob_result_free(&mut out);
        ffi::rob_error_free(&mut err);
        result
    }
}

fn execute_push(request: &PushRequest) -> Result<ImageInfo> {
    let image = cstring(request.image.as_bytes())?;
    let destination = cstring(request.destination.as_bytes())?;
    let username = opt_cstring(&request.username)?;
    let password = opt_cstring(&request.password)?;
    let format = opt_cstring(request.format.map(ImageFormat::as_abi).unwrap_or(""))?;
    let slot = request
        .on_log
        .clone()
        .map(|callback| LogTarget { callback });
    let log_user = slot
        .as_ref()
        .map(|target| target as *const LogTarget as *mut c_void)
        .unwrap_or(std::ptr::null_mut());
    let raw = RobPushRequest {
        image: image.as_ptr(),
        destination: destination.as_ptr(),
        username: username.as_ptr(),
        password: password.as_ptr(),
        format: format.as_ptr(),
        log_fn: if slot.is_some() {
            Some(log_trampoline)
        } else {
            None
        },
        log_user,
        cancel_token: token_id(&request.cancel),
        insecure: i32::from(request.insecure),
        _pad: 0,
    };
    unsafe {
        let mut out = RobResult::zero();
        let mut err = RobError::zero();
        let code = ffi::rob_push(&raw, &mut out, &mut err);
        let result = match take_status(code, &err) {
            Ok(()) => Ok(take_info(&out)),
            Err(error) => Err(error),
        };
        ffi::rob_result_free(&mut out);
        ffi::rob_error_free(&mut err);
        result
    }
}

struct HeldConfig {
    _owned: Vec<CString>,
    _opts: CStringList,
    raw: RobConfig,
}

impl HeldConfig {
    fn from_config(config: &Config) -> Result<Self> {
        let mut owned = Vec::new();
        let storage_root = hold_path(&mut owned, config.storage_root.as_deref())?;
        let run_root = hold_path(&mut owned, config.run_root.as_deref())?;
        let storage_driver = hold_str(
            &mut owned,
            config
                .storage_driver
                .map(StorageDriver::as_abi)
                .unwrap_or(""),
        )?;
        let registries_conf = hold_path(&mut owned, config.registries_conf.as_deref())?;
        let signature_policy = hold_path(&mut owned, config.signature_policy.as_deref())?;
        let auth_file = hold_path(&mut owned, config.auth_file.as_deref())?;
        let log_level = hold_str(&mut owned, config.log_level.as_abi())?;
        let opts = CStringList::from_strings(config.storage_opts.iter().map(String::as_str))?;
        let raw = RobConfig {
            storage_root,
            run_root,
            storage_driver,
            registries_conf,
            signature_policy,
            auth_file,
            log_level,
            storage_opts: opts.as_ptr(),
            storage_opt_count: opts.len(),
            insecure: i32::from(config.insecure),
            _pad: 0,
        };
        Ok(Self {
            _owned: owned,
            _opts: opts,
            raw,
        })
    }
}

fn hold_path(owned: &mut Vec<CString>, path: Option<&Path>) -> Result<*const c_char> {
    match path {
        Some(path) => {
            let c = cstring_path(path)?;
            let ptr = c.as_ptr();
            owned.push(c);
            Ok(ptr)
        }
        None => Ok(std::ptr::null()),
    }
}

fn hold_str(owned: &mut Vec<CString>, value: &str) -> Result<*const c_char> {
    if value.is_empty() {
        return Ok(std::ptr::null());
    }
    let c = cstring(value.as_bytes())?;
    let ptr = c.as_ptr();
    owned.push(c);
    Ok(ptr)
}

struct OptCString {
    _owned: Option<CString>,
    ptr: *const c_char,
}

impl OptCString {
    fn as_ptr(&self) -> *const c_char {
        self.ptr
    }
}

fn opt_cstring(value: &str) -> Result<OptCString> {
    if value.is_empty() {
        return Ok(OptCString {
            _owned: None,
            ptr: std::ptr::null(),
        });
    }
    let owned = cstring(value.as_bytes())?;
    let ptr = owned.as_ptr();
    Ok(OptCString {
        _owned: Some(owned),
        ptr,
    })
}

struct CStringList {
    _owned: Vec<CString>,
    ptrs: Vec<*const c_char>,
}

impl CStringList {
    fn from_strings<I, S>(items: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let mut owned = Vec::new();
        for item in items {
            owned.push(cstring(item.as_ref())?);
        }
        let ptrs = owned.iter().map(|item| item.as_ptr()).collect();
        Ok(Self {
            _owned: owned,
            ptrs,
        })
    }

    fn as_ptr(&self) -> *const *const c_char {
        if self.ptrs.is_empty() {
            std::ptr::null()
        } else {
            self.ptrs.as_ptr()
        }
    }

    fn len(&self) -> usize {
        self.ptrs.len()
    }
}

fn cstring(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes.to_vec()).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "string contains an interior NUL byte",
            "",
        )
    })
}

fn cstring_path(path: &Path) -> Result<CString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        cstring(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        let text = path.to_str().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("path is not valid Unicode: {}", path.display()),
                "",
            )
        })?;
        cstring(text.as_bytes())
    }
}

fn token_id(token: &Option<CancelToken>) -> u64 {
    token.as_ref().map(|token| token.inner.id).unwrap_or(0)
}

fn take_info(result: &RobResult) -> ImageInfo {
    let image_id = unsafe { read_buf(&result.image_id) };
    let digest = nonempty(unsafe { read_buf(&result.digest) });
    let reference = nonempty(unsafe { read_buf(&result.reference) });
    ImageInfo {
        image_id,
        digest,
        reference,
    }
}

fn nonempty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

struct LogTarget {
    callback: Arc<dyn Fn(LogRecord) + Send + Sync>,
}

unsafe extern "C" fn log_trampoline(
    user: *mut c_void,
    level: i32,
    data: *const c_char,
    len: usize,
) {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        if user.is_null() {
            return;
        }
        let target = unsafe { &*(user as *const LogTarget) };
        let message = if data.is_null() || len == 0 {
            String::new()
        } else {
            let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) };
            String::from_utf8_lossy(bytes).into_owned()
        };
        (target.callback)(LogRecord {
            stream: LogStream::from_raw(level),
            message,
        });
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_reports_the_linked_engine() {
        let version = buildah_version();
        assert!(!version.is_empty());
        #[cfg(rob_stub)]
        assert_eq!(version, "unsupported");
        #[cfg(not(rob_stub))]
        assert!(version.starts_with('1'), "{version}");
    }

    #[test]
    fn startup_on_the_stub_is_unsupported() {
        #[cfg(all(rob_stub, not(target_os = "macos")))]
        {
            let err = startup().expect_err("stub startup");
            assert_eq!(err.code(), ErrorCode::Unsupported);
            assert!(err.to_string().to_lowercase().contains("linux"));
        }
        #[cfg(target_os = "macos")]
        startup().expect("macos startup does not boot a guest");
    }

    #[test]
    fn cancel_token_roundtrip() {
        let token = CancelToken::new().expect("token");
        token.cancel();
        let clone = token.clone();
        clone.cancel();
        drop(clone);
        drop(token);
    }

    #[test]
    fn missing_dockerfile_is_invalid() {
        let err = BuildRequest::new("/no/such/Dockerfile", "/no/such/context")
            .prepare()
            .expect_err("missing");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn prepare_accepts_a_dockerfile_and_directory() {
        let dir = std::env::temp_dir().join(format!("rob-prep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("Dockerfile");
        std::fs::write(&file, "FROM scratch\n").unwrap();
        let prepared = BuildRequest::new(&file, &dir).prepare().expect("prepare");
        assert!(prepared.dockerfile.is_absolute());
        assert!(prepared.context_dir.is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
