// SPDX-License-Identifier: Apache-2.0

//! macOS host for the Linux Buildah engine.
//!
//! `startup` does not boot anything, so `--help` stays local. The guest starts
//! on the first build, tag, or push: virtiofs devices are fixed for the life of
//! the VM, and the build context is only known then.

use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use dispatch2::DispatchQueue;
use dispatch2::DispatchRetained;
use objc2::rc::Retained;
use objc2_virtualization::VZVirtualMachine;
use oci_util::vm::{
    Export, ShareRequest, VmError, VmErrorKind, guest_path, lines_from_attestation,
    materialize_embedded, plan_shares, start_vm, stop_virtual_machine, virtualization_supported,
    wait_readable,
};

use crate::builder::{BuildRequest, CancelToken, ImageInfo, LogRecord, LogStream, PreparedPaths};
use crate::config::{Config, EngineHost, ImageFormat, StorageDriver};
use crate::error::{Error, ErrorCode};
use crate::guest_config::GUEST;
use crate::proto as rob_proto;
use crate::proto::{
    GuestFrame, HostFrame, Init, PROTOCOL_VERSION, read_guest_frame, write_host_frame,
};

struct Shared {
    jobs: std::sync::mpsc::Sender<Job>,
    write: Arc<Mutex<Option<File>>>,
    early_cancel: Arc<Mutex<HashSet<u64>>>,
    config: Config,
    join: Option<JoinHandle<()>>,
}

enum Job {
    Ensure {
        exports: Vec<Export>,
        reply: std::sync::mpsc::Sender<Result<Vec<Export>, Error>>,
    },
    Rpc {
        frame: Box<HostFrame>,
        on_log: Option<Arc<dyn Fn(LogRecord) + Send + Sync>>,
        reply: std::sync::mpsc::Sender<Result<ImageInfo, Error>>,
    },
    Stop {
        reply: std::sync::mpsc::Sender<Result<(), Error>>,
    },
}

struct Guest {
    vm: Retained<VZVirtualMachine>,
    queue: DispatchRetained<DispatchQueue>,
    _console: JoinHandle<()>,
    read: File,
    exports: Vec<Export>,
}

static SESSION: Mutex<Option<Shared>> = Mutex::new(None);

pub(crate) fn open(mut config: Config) -> Result<(), Error> {
    if !virtualization_supported() {
        return Err(fail(
            ErrorCode::Prerequisite,
            "Apple Virtualization.framework is not available on this Mac",
        ));
    }
    if !oci_util::vm::entitlement_present() {
        return Err(map_vm(oci_util::vm::missing_entitlement(
            GUEST.no_self_sign_env,
        )));
    }
    config.signature_policy =
        crate::policy::effective_signature_policy(config.signature_policy.as_deref())?;
    let (kernel, initrd) = locate_artifacts()?;
    let mut slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    if slot.is_some() {
        return Err(fail(ErrorCode::State, "store is already open"));
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let write = Arc::new(Mutex::new(None));
    let early_cancel = Arc::new(Mutex::new(HashSet::new()));
    let write_worker = Arc::clone(&write);
    let early_worker = Arc::clone(&early_cancel);
    let config_worker = config.clone();
    let join = thread::Builder::new()
        .name(GUEST.thread_name.into())
        .spawn(move || {
            worker(
                rx,
                write_worker,
                early_worker,
                config_worker,
                kernel,
                initrd,
            )
        })
        .map_err(|err| fail(ErrorCode::Internal, format!("guest thread: {err}")))?;
    *slot = Some(Shared {
        jobs: tx,
        write,
        early_cancel,
        config,
        join: Some(join),
    });
    Ok(())
}

pub(crate) fn build(request: &BuildRequest, paths: &PreparedPaths) -> Result<ImageInfo, Error> {
    // Reject OCI isolation before any virtiofs device is created. The guest
    // has no runc or crun; chroot is the supported isolation.
    let isolation = request.isolation.for_engine(EngineHost::MacosGuest)?;
    let staged = stage_build_context(paths)?;
    let exports = with_session(|shared| {
        prepare_dirs(&shared.config)?;
        let planned = plan_shares(ShareRequest {
            context: Some(&staged.context_dir),
            dockerfile: Some(&staged.dockerfile),
            storage_root: shared.config.storage_root.as_deref(),
            run_root: shared.config.run_root.as_deref(),
            signature_policy: shared.config.signature_policy.as_deref(),
            registries_conf: shared.config.registries_conf.as_deref(),
            auth_file: shared.config.auth_file.as_deref(),
        })
        .map_err(|err| fail(ErrorCode::InvalidArgument, err))?;
        call_ensure(shared, planned)
    })?;
    let frame = HostFrame::Build(rob_proto::Build {
        dockerfile: map_path(&staged.dockerfile, &exports)?,
        context_dir: map_path(&staged.context_dir, &exports)?,
        tag: request.tag.clone().unwrap_or_default(),
        target: request.target.clone().unwrap_or_default(),
        isolation: isolation.to_string(),
        format: request.format.as_abi().to_string(),
        pull: request.pull.as_abi().to_string(),
        os: request.os.clone().unwrap_or_default(),
        arch: request.arch.clone().unwrap_or_default(),
        variant: request.variant.clone().unwrap_or_default(),
        build_args: request
            .build_args
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        labels: request
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        layers: i32::from(request.layers),
        no_cache: request.no_cache,
        squash: request.squash,
        quiet: request.quiet,
        cancel_token: request
            .cancel
            .as_ref()
            .map(CancelToken::raw_id)
            .unwrap_or(0),
        excludes: staged.excludes,
    });
    rpc(frame, request.on_log.clone())
}

pub(crate) fn tag(image: &str, new_name: &str) -> Result<(), Error> {
    let _exports = ensure_config_only()?;
    let info = rpc(
        HostFrame::Tag {
            image: image.to_string(),
            new_name: new_name.to_string(),
        },
        None,
    )?;
    let _ = info;
    Ok(())
}

pub(crate) fn push(request: &crate::builder::PushRequest) -> Result<ImageInfo, Error> {
    let _exports = ensure_config_only()?;

    if request.sign {
        with_session(|shared| {
            let _signing = crate::notary::validate_signing_config(
                shared.config.signing_key.as_deref(),
                &shared.config.signing_cert_chain,
            )?;
            Ok(())
        })?;
    }

    let info = rpc(
        HostFrame::Push(rob_proto::Push {
            image: request.image.clone(),
            destination: request.destination.clone(),
            username: request.username.clone(),
            password: request.password.clone(),
            format: request
                .format
                .map(ImageFormat::as_abi)
                .unwrap_or("")
                .to_string(),
            insecure: request.insecure,
            cancel_token: request
                .cancel
                .as_ref()
                .map(CancelToken::raw_id)
                .unwrap_or(0),
        }),
        request.on_log.clone(),
    )?;
    if request.sign {
        with_session(|shared| {
            let material = crate::notary::validate_signing_config(
                shared.config.signing_key.as_deref(),
                &shared.config.signing_cert_chain,
            )?
            .ok_or_else(|| {
                fail(
                    ErrorCode::InvalidArgument,
                    "signature requested but no signing key is configured",
                )
            })?;
            let registry = crate::registry::Registry::parse(
                &request.destination,
                &request.username,
                &request.password,
                request.insecure || shared.config.insecure,
            )?;
            registry.sign_push(&material)?;
            Ok(())
        })?;
    }
    Ok(info)
}

pub(crate) fn shutdown() -> Result<(), Error> {
    let mut slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    let Some(mut shared) = slot.take() else {
        return Err(fail(ErrorCode::State, "store is not open"));
    };
    let (tx, rx) = std::sync::mpsc::channel();
    shared
        .jobs
        .send(Job::Stop { reply: tx })
        .map_err(|_| fail(ErrorCode::Internal, "guest thread has stopped"))?;
    rx.recv()
        .map_err(|_| fail(ErrorCode::Internal, "guest thread dropped shutdown"))??;
    if let Some(join) = shared.join.take() {
        let _ = join.join();
    }
    Ok(())
}

pub(crate) fn diagnose() -> Result<String, Error> {
    let mut lines = Vec::new();
    let mut blocked = false;
    if virtualization_supported() {
        lines.push("[ok] Apple Virtualization.framework is available".to_string());
    } else {
        blocked = true;
        lines
            .push("[fail] Apple Virtualization.framework is not available on this Mac".to_string());
    }
    if oci_util::vm::entitlement_present() {
        lines.push("[ok] com.apple.security.virtualization entitlement".to_string());
    } else {
        blocked = true;
        let err = map_vm(oci_util::vm::missing_entitlement(GUEST.no_self_sign_env));
        lines.push(format!("[fail] {}", err.message()));
        lines.push(err.detail().to_string());
    }
    match locate_artifacts() {
        Ok((kernel, initrd)) => {
            lines.push(format!("[ok] embedded guest kernel {}", kernel.display()));
            lines.push(format!(
                "[ok] embedded guest initramfs {}",
                initrd.display()
            ));
        }
        Err(err) => {
            blocked = true;
            lines.push(format!("[fail] {}", err.message()));
            if !err.detail().is_empty() {
                lines.push(err.detail().to_string());
            }
        }
    }
    lines.extend(lines_from_attestation(EMBEDDED_ATTESTATION));
    let status = if blocked { "blocked" } else { "ready" };
    let mut report = format!("status: {status}\n");
    report.push_str(&lines.join("\n"));
    report.push('\n');
    if blocked {
        Err(Error::new(
            ErrorCode::Prerequisite,
            "macOS guest image is not ready",
            report,
        ))
    } else {
        Ok(report)
    }
}

pub(crate) fn cancel(token: u64) {
    let slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    let Some(shared) = slot.as_ref() else {
        return;
    };
    let mut write = shared
        .write
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let Some(file) = write.as_mut() {
        let _ = write_host_frame(file, &HostFrame::Cancel { token });
    } else {
        drop(write);
        shared
            .early_cancel
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(token);
    }
}

fn ensure_config_only() -> Result<Vec<Export>, Error> {
    with_session(|shared| {
        prepare_dirs(&shared.config)?;
        let planned = plan_shares(ShareRequest {
            context: None,
            dockerfile: None,
            storage_root: shared.config.storage_root.as_deref(),
            run_root: shared.config.run_root.as_deref(),
            signature_policy: shared.config.signature_policy.as_deref(),
            registries_conf: shared.config.registries_conf.as_deref(),
            auth_file: shared.config.auth_file.as_deref(),
        })
        .map_err(|err| fail(ErrorCode::InvalidArgument, err))?;
        call_ensure(shared, planned)
    })
}

fn with_session<T>(body: impl FnOnce(&Shared) -> Result<T, Error>) -> Result<T, Error> {
    let slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    let shared = slot
        .as_ref()
        .ok_or_else(|| fail(ErrorCode::State, "store is not open"))?;
    body(shared)
}

fn call_ensure(shared: &Shared, exports: Vec<Export>) -> Result<Vec<Export>, Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    shared
        .jobs
        .send(Job::Ensure { exports, reply: tx })
        .map_err(|_| fail(ErrorCode::Internal, "guest thread has stopped"))?;
    rx.recv()
        .map_err(|_| fail(ErrorCode::Internal, "guest thread dropped ensure"))?
}

fn rpc(
    frame: HostFrame,
    on_log: Option<Arc<dyn Fn(LogRecord) + Send + Sync>>,
) -> Result<ImageInfo, Error> {
    let slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    let shared = slot
        .as_ref()
        .ok_or_else(|| fail(ErrorCode::State, "store is not open"))?;
    let token = match &frame {
        HostFrame::Build(build) => build.cancel_token,
        HostFrame::Push(push) => push.cancel_token,
        _ => 0,
    };
    let (tx, rx) = std::sync::mpsc::channel();
    shared
        .jobs
        .send(Job::Rpc {
            frame: Box::new(frame),
            on_log,
            reply: tx,
        })
        .map_err(|_| fail(ErrorCode::Internal, "guest thread has stopped"))?;
    drop(slot);
    if token != 0 {
        flush_early(token);
    }
    rx.recv()
        .map_err(|_| fail(ErrorCode::Internal, "guest thread dropped the call"))?
}

fn flush_early(token: u64) {
    let slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    let Some(shared) = slot.as_ref() else {
        return;
    };
    let fire = shared
        .early_cancel
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .remove(&token);
    if !fire {
        return;
    }
    let mut write = shared
        .write
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let Some(file) = write.as_mut() {
        let _ = write_host_frame(file, &HostFrame::Cancel { token });
    } else {
        drop(write);
        shared
            .early_cancel
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(token);
    }
}

fn prepare_dirs(config: &Config) -> Result<(), Error> {
    for path in [config.storage_root.as_ref(), config.run_root.as_ref()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(path).map_err(|err| {
            fail(
                ErrorCode::InvalidArgument,
                format!("{}: {err}", path.display()),
            )
        })?;
    }
    Ok(())
}

fn worker(
    rx: std::sync::mpsc::Receiver<Job>,
    write: Arc<Mutex<Option<File>>>,
    early_cancel: Arc<Mutex<HashSet<u64>>>,
    config: Config,
    kernel: PathBuf,
    initrd: PathBuf,
) {
    let _ = early_cancel;
    let mut guest: Option<Guest> = None;
    while let Ok(job) = rx.recv() {
        match job {
            Job::Ensure { exports, reply } => {
                let result = ensure_guest(&mut guest, &exports, &write, &config, &kernel, &initrd);
                let _ = reply.send(result);
            }
            Job::Rpc {
                frame,
                on_log,
                reply,
            } => {
                let result = match guest.as_mut() {
                    Some(guest) => exchange(&mut guest.read, &write, &frame, on_log.as_deref()),
                    None => Err(fail(ErrorCode::Internal, "guest is not running")),
                };
                let _ = reply.send(result);
            }
            Job::Stop { reply } => {
                if let Some(guest) = guest.as_mut() {
                    let _ = exchange(&mut guest.read, &write, &HostFrame::Shutdown, None);
                }
                if let Some(guest) = guest.take() {
                    guest.stop();
                }
                *write.lock().unwrap_or_else(|poison| poison.into_inner()) = None;
                let _ = reply.send(Ok(()));
                break;
            }
        }
    }
}

fn ensure_guest(
    guest: &mut Option<Guest>,
    exports: &[Export],
    write: &Arc<Mutex<Option<File>>>,
    config: &Config,
    kernel: &Path,
    initrd: &Path,
) -> Result<Vec<Export>, Error> {
    if let Some(existing) = guest.as_ref() {
        for export in exports {
            let covered = existing
                .exports
                .iter()
                .any(|have| export.host.starts_with(&have.host));
            if !covered {
                return Err(fail(
                    ErrorCode::InvalidArgument,
                    format!(
                        "{} is not inside a directory the running guest can see; shutdown before using a new directory",
                        export.host.display()
                    ),
                ));
            }
        }
        return Ok(existing.exports.clone());
    }
    let mut started = boot(kernel, initrd, exports, write)?;
    let initialized = init_frame(config, exports)
        .and_then(|init| exchange(&mut started.read, write, &HostFrame::Init(init), None));
    if let Err(err) = initialized {
        started.stop();
        *write.lock().unwrap_or_else(|poison| poison.into_inner()) = None;
        return Err(err);
    }
    let booted = started.exports.clone();
    *guest = Some(started);
    Ok(booted)
}

fn init_frame(config: &Config, exports: &[Export]) -> Result<Init, Error> {
    Ok(Init {
        storage_root: map_optional(config.storage_root.as_deref(), exports)?,
        run_root: map_optional(config.run_root.as_deref(), exports)?,
        storage_driver: config
            .storage_driver
            .map(StorageDriver::as_abi)
            .unwrap_or("vfs")
            .to_string(),
        storage_opts: config.storage_opts.clone(),
        registries_conf: map_optional(config.registries_conf.as_deref(), exports)?,
        signature_policy: map_optional(config.signature_policy.as_deref(), exports)?,
        auth_file: map_optional(config.auth_file.as_deref(), exports)?,
        insecure: config.insecure,
        log_level: config.log_level.as_abi().to_string(),
    })
}

fn map_optional(path: Option<&Path>, exports: &[Export]) -> Result<String, Error> {
    match path {
        None => Ok(String::new()),
        Some(path) => {
            guest_path(path, exports).map_err(|err| fail(ErrorCode::InvalidArgument, err))
        }
    }
}

fn map_path(path: &Path, exports: &[Export]) -> Result<String, Error> {
    guest_path(path, exports).map_err(|err| fail(ErrorCode::InvalidArgument, err))
}

/// Filtered copy of the build context. The same directory is reused for a
/// given host context so a later build still sits inside the share the
/// running guest already has. Children are replaced; the directory inode stays.
fn stage_build_context(paths: &PreparedPaths) -> Result<PreparedPaths, Error> {
    let root = std::env::temp_dir().join(format!("oci-builder-context-{}", std::process::id()));
    std::fs::create_dir_all(&root).map_err(|err| {
        fail(
            ErrorCode::Internal,
            format!("creating context stage root: {err}"),
        )
    })?;
    let dest = root.join(stage_key(&paths.context_dir));
    if dest.exists() {
        clear_children(&dest)?;
    }
    std::fs::create_dir_all(&dest).map_err(|err| {
        fail(
            ErrorCode::Internal,
            format!("creating staged context: {err}"),
        )
    })?;
    crate::ignore::stage_context(
        &paths.context_dir,
        &paths.dockerfile,
        &paths.excludes,
        &dest,
    )?;
    let rel = paths
        .dockerfile
        .strip_prefix(&paths.context_dir)
        .map_err(|_| {
            fail(
                ErrorCode::InvalidArgument,
                format!(
                    "dockerfile {} is outside the build context {}",
                    paths.dockerfile.display(),
                    paths.context_dir.display()
                ),
            )
        })?;
    Ok(PreparedPaths {
        dockerfile: dest.join(rel),
        context_dir: dest,
        excludes: paths.excludes.clone(),
    })
}

fn stage_key(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path.as_os_str().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn clear_children(dir: &Path) -> Result<(), Error> {
    for entry in std::fs::read_dir(dir).map_err(|err| {
        fail(
            ErrorCode::Internal,
            format!("reading staged context: {err}"),
        )
    })? {
        let entry = entry.map_err(|err| {
            fail(
                ErrorCode::Internal,
                format!("reading staged context: {err}"),
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|err| {
            fail(
                ErrorCode::Internal,
                format!("reading staged context: {err}"),
            )
        })?;
        let result = if file_type.is_symlink() || file_type.is_file() {
            std::fs::remove_file(&path)
        } else {
            std::fs::remove_dir_all(&path)
        };
        result.map_err(|err| {
            fail(
                ErrorCode::Internal,
                format!("clearing staged context: {err}"),
            )
        })?;
    }
    Ok(())
}

fn exchange(
    read: &mut File,
    write: &Arc<Mutex<Option<File>>>,
    frame: &HostFrame,
    on_log: Option<&(dyn Fn(LogRecord) + Send + Sync)>,
) -> Result<ImageInfo, Error> {
    write_locked(write, frame)?;
    loop {
        let guest = read_guest_frame(read).map_err(io_err)?;
        match guest {
            GuestFrame::Log { stream, message } => {
                if let Some(callback) = on_log {
                    callback(LogRecord {
                        stream: log_stream(stream),
                        message,
                    });
                }
            }
            GuestFrame::Result {
                image_id,
                digest,
                reference,
            } => {
                return Ok(ImageInfo {
                    image_id,
                    digest: nonempty(digest),
                    reference: nonempty(reference),
                });
            }
            GuestFrame::Error {
                code,
                message,
                detail,
            } => return Err(Error::new(ErrorCode::from_raw(code), message, detail)),
            GuestFrame::Hello { protocol } => {
                return Err(Error::new(
                    ErrorCode::Prerequisite,
                    "unexpected guest protocol hello",
                    format!("guest reported protocol version {protocol} after negotiation"),
                ));
            }
        }
    }
}

fn write_locked(write: &Arc<Mutex<Option<File>>>, frame: &HostFrame) -> Result<(), Error> {
    let mut guard = write.lock().unwrap_or_else(|poison| poison.into_inner());
    let file = guard
        .as_mut()
        .ok_or_else(|| fail(ErrorCode::Internal, "guest socket is not connected"))?;
    write_host_frame(file, frame).map_err(io_err)
}

fn log_stream(stream: u8) -> LogStream {
    match stream {
        rob_proto::LOG_PROGRESS => LogStream::Progress,
        rob_proto::LOG_WARN => LogStream::Warn,
        rob_proto::LOG_ERROR => LogStream::Error,
        _ => LogStream::Info,
    }
}

fn nonempty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn boot(
    kernel: &Path,
    initrd: &Path,
    exports: &[Export],
    write: &Arc<Mutex<Option<File>>>,
) -> Result<Guest, Error> {
    let started = start_vm(&GUEST, kernel, initrd, exports).map_err(map_vm)?;
    *write.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(started.write);
    let mut guest = Guest {
        vm: started.vm,
        queue: started.queue,
        _console: started.console,
        read: started.read,
        exports: exports.to_vec(),
    };
    if let Err(err) = handshake(&mut guest.read, write) {
        guest.stop();
        *write.lock().unwrap_or_else(|poison| poison.into_inner()) = None;
        return Err(err);
    }
    Ok(guest)
}

fn handshake(read: &mut File, write: &Arc<Mutex<Option<File>>>) -> Result<(), Error> {
    write_locked(
        write,
        &HostFrame::Hello {
            protocol: PROTOCOL_VERSION,
        },
    )?;
    wait_readable(read, GUEST.handshake_timeout).map_err(|err| {
        Error::new(
            ErrorCode::Prerequisite,
            "guest protocol handshake failed",
            format!(
                "host expects protocol version {PROTOCOL_VERSION}; the embedded guest did not respond: {err}. Rebuild the guest with `cargo xtask guest`."
            ),
        )
    })?;
    match read_guest_frame(read) {
        Ok(GuestFrame::Hello { protocol }) if protocol == PROTOCOL_VERSION => Ok(()),
        Ok(GuestFrame::Hello { protocol }) => Err(Error::new(
            ErrorCode::Prerequisite,
            "guest protocol mismatch",
            format!(
                "host expects protocol version {PROTOCOL_VERSION}, guest implements {protocol}; rebuild the guest with `cargo xtask guest`"
            ),
        )),
        Ok(GuestFrame::Error {
            code,
            message,
            detail,
        }) => Err(Error::new(ErrorCode::from_raw(code), message, detail)),
        Ok(frame) => Err(Error::new(
            ErrorCode::Prerequisite,
            "guest protocol handshake failed",
            format!("expected a protocol hello, received {frame:?}"),
        )),
        Err(err) => Err(Error::new(
            ErrorCode::Prerequisite,
            "guest protocol handshake failed",
            format!(
                "host expects protocol version {PROTOCOL_VERSION}; guest closed or rejected the handshake: {err}. Rebuild the guest with `cargo xtask guest`."
            ),
        )),
    }
}

impl Guest {
    fn stop(self) {
        stop_virtual_machine(self.vm, &self.queue);
    }
}

const EMBEDDED_KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rob-guest-vmlinuz.zst"));
const EMBEDDED_INITRD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rob-guest-initramfs.zst"));
const EMBEDDED_ATTESTATION: &str =
    include_str!(concat!(env!("OUT_DIR"), "/rob-guest-attestation.json"));

fn locate_artifacts() -> Result<(PathBuf, PathBuf), Error> {
    materialize_embedded(&GUEST, EMBEDDED_KERNEL, EMBEDDED_INITRD).map_err(map_vm)
}

fn map_vm(err: VmError) -> Error {
    let code = match err.kind {
        VmErrorKind::InvalidArgument => ErrorCode::InvalidArgument,
        VmErrorKind::Prerequisite => ErrorCode::Prerequisite,
        VmErrorKind::State => ErrorCode::State,
        VmErrorKind::Internal => ErrorCode::Internal,
    };
    Error::new(code, err.message, err.detail)
}

fn io_err(err: io::Error) -> Error {
    fail(ErrorCode::Internal, format!("guest socket: {err}"))
}

fn fail(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message, "")
}
