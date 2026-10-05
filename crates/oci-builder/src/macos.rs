// SPDX-License-Identifier: Apache-2.0

//! macOS host for the Linux Buildah engine.
//!
//! `startup` does not boot anything, so `--help` stays local. The guest starts
//! on the first build, tag, or push: virtiofs devices are fixed for the life of
//! the VM, and the build context is only known then.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use std::{env, sync::Mutex as StdMutex};

use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchQueueAttr, DispatchRetained};
use libc::c_int;
use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_foundation::{NSArray, NSError, NSFileHandle, NSString, NSURL};
use objc2_virtualization::{
    VZDirectorySharingDeviceConfiguration, VZEntropyDeviceConfiguration,
    VZFileHandleSerialPortAttachment, VZGenericPlatformConfiguration, VZLinuxBootLoader,
    VZNATNetworkDeviceAttachment, VZNetworkDeviceConfiguration, VZSerialPortConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration, VZVirtioEntropyDeviceConfiguration,
    VZVirtioFileSystemDeviceConfiguration, VZVirtioNetworkDeviceConfiguration,
    VZVirtioSocketDevice, VZVirtioSocketDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration,
};
use crate::proto as rob_proto;
use crate::proto::{GuestFrame, HostFrame, Init, VSOCK_PORT, read_guest_frame, write_host_frame};

use crate::builder::{BuildRequest, CancelToken, ImageInfo, LogRecord, LogStream, PreparedPaths};
use crate::config::{Config, ImageFormat, StorageDriver};
use crate::error::{Error, ErrorCode};
use crate::shares::{Export, ShareRequest, guest_path, plan_shares};

const BOOT_TIMEOUT: Duration = Duration::from_secs(30);

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

pub(crate) fn open(config: Config) -> Result<(), Error> {
    if !virtualization_supported() {
        return Err(fail(
            ErrorCode::Prerequisite,
            "Apple Virtualization.framework is not available on this Mac",
        ));
    }
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
        .name("oci-builder-guest".into())
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
    let exports = with_session(|shared| {
        prepare_dirs(&shared.config)?;
        let planned = plan_shares(ShareRequest {
            context: Some(&paths.context_dir),
            dockerfile: Some(&paths.dockerfile),
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
        dockerfile: map_path(&paths.dockerfile, &exports)?,
        context_dir: map_path(&paths.context_dir, &exports)?,
        tag: request.tag.clone().unwrap_or_default(),
        target: request.target.clone().unwrap_or_default(),
        isolation: request.isolation.as_abi().to_string(),
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
    rpc(
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
    )
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
    match locate_artifacts() {
        Ok((kernel, initrd)) => {
            let embedded = kernel.starts_with(guest_cache_dir());
            let source = if embedded { "embedded guest" } else { "guest" };
            lines.push(format!("[ok] {source} kernel {}", kernel.display()));
            lines.push(format!("[ok] {source} initramfs {}", initrd.display()));
        }
        Err(err) => {
            blocked = true;
            lines.push(format!("[fail] {}", err.message()));
            if !err.detail().is_empty() {
                lines.push(err.detail().to_string());
            }
        }
    }
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
    let queue = DispatchQueue::new("oci-builder.vm", DispatchQueueAttr::SERIAL);
    let (console_read, config) = vm_config(kernel, initrd, exports)?;
    let console = spawn_console(console_read);
    // The virtual machine object is not Send. Create it on its queue and move
    // only the raw pointer back to this thread. Every method call goes back
    // onto that queue.
    let config_ptr = Retained::as_ptr(&config) as usize;
    let queue_ptr = &*queue as *const DispatchQueue as usize;
    let vm_slot = Arc::new(AtomicPtr::new(std::ptr::null_mut()));
    let vm_slot_queue = Arc::clone(&vm_slot);
    queue.exec_sync(move || {
        let config = unsafe { &*(config_ptr as *const VZVirtualMachineConfiguration) };
        let queue_ref = unsafe { &*(queue_ptr as *const DispatchQueue) };
        let vm = unsafe {
            VZVirtualMachine::initWithConfiguration_queue(
                VZVirtualMachine::alloc(),
                config,
                queue_ref,
            )
        };
        vm_slot_queue.store(Retained::into_raw(vm), Ordering::SeqCst);
    });
    let vm = unsafe { Retained::from_raw(vm_slot.load(Ordering::SeqCst)) }
        .ok_or_else(|| fail(ErrorCode::Internal, "virtual machine was not created"))?;
    let vm_ptr = Retained::as_ptr(&vm) as usize;
    wait_on_queue(&queue, BOOT_TIMEOUT, move |done| {
        let vm = unsafe { &*(vm_ptr as *const VZVirtualMachine) };
        let once = StdMutex::new(Some(done));
        unsafe {
            vm.startWithCompletionHandler(&RcBlock::new(move |err: *mut NSError| {
                if let Some(done) = once
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .take()
                {
                    done(ns_result(err));
                }
            }));
        }
    })?;
    let fd = connect_vsock(vm_ptr, &queue)?;
    prepare_fd(fd);
    let write_fd = unsafe { libc::dup(fd) };
    if write_fd < 0 {
        unsafe { libc::close(fd) };
        return Err(io_err(io::Error::last_os_error()));
    }
    prepare_fd(write_fd);
    let read = unsafe { File::from(OwnedFd::from_raw_fd(fd)) };
    let write_file = unsafe { File::from(OwnedFd::from_raw_fd(write_fd)) };
    *write.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(write_file);
    Ok(Guest {
        vm,
        queue,
        _console: console,
        read,
        exports: exports.to_vec(),
    })
}

fn connect_vsock(vm_ptr: usize, queue: &DispatchQueue) -> Result<c_int, Error> {
    // One connect at a time. The guest accepts a single socket; abandoning an
    // in-flight connect would leave it talking to a descriptor this side dropped.
    let deadline = Instant::now() + BOOT_TIMEOUT;
    let mut last = String::from("guest has not opened the virtio socket");
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt = wait_on_queue(queue, remaining, move |done| {
            let vm = unsafe { &*(vm_ptr as *const VZVirtualMachine) };
            let once = StdMutex::new(Some(done));
            unsafe {
                let devices = vm.socketDevices();
                if devices.count() == 0 {
                    if let Some(done) = once
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .take()
                    {
                        done(Err("virtual machine has no virtio socket device".into()));
                    }
                    return;
                }
                let device = devices.objectAtIndex(0);
                let Ok(socket) = device.downcast::<VZVirtioSocketDevice>() else {
                    if let Some(done) = once
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .take()
                    {
                        done(Err("socket device is not a virtio socket".into()));
                    }
                    return;
                };
                socket.connectToPort_completionHandler(
                    VSOCK_PORT,
                    &RcBlock::new(
                        move |conn: *mut objc2_virtualization::VZVirtioSocketConnection,
                              err: *mut NSError| {
                            let Some(done) = once
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .take()
                            else {
                                return;
                            };
                            if conn.is_null() {
                                done(Err(ns_message(err)));
                                return;
                            }
                            let raw = (*conn).fileDescriptor();
                            if raw < 0 {
                                done(Err("virtio socket connection is closed".into()));
                                return;
                            }
                            let fd = libc::dup(raw);
                            if fd < 0 {
                                done(Err(io::Error::last_os_error().to_string()));
                            } else {
                                done(Ok(fd));
                            }
                        },
                    ),
                );
            }
        });
        match attempt {
            Ok(fd) => return Ok(fd),
            Err(err) if err.message() == "timed out waiting for the virtual machine" => {
                return Err(fail(ErrorCode::Prerequisite, last));
            }
            Err(err) => {
                last = err.message().to_string();
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
    Err(fail(ErrorCode::Prerequisite, last))
}

fn wait_on_queue<T, F>(queue: &DispatchQueue, timeout: Duration, start: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(Box<dyn FnOnce(Result<T, String>) + Send>) + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    queue.exec_async(move || {
        let tx = tx;
        start(Box::new(move |result| {
            let _ = tx.send(result);
        }));
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(message)) => Err(fail(ErrorCode::Prerequisite, message)),
        Err(_) => Err(fail(
            ErrorCode::Prerequisite,
            "timed out waiting for the virtual machine",
        )),
    }
}

fn vm_config(
    kernel: &Path,
    initrd: &Path,
    exports: &[Export],
) -> Result<(OwnedFd, Retained<VZVirtualMachineConfiguration>), Error> {
    let config = unsafe { VZVirtualMachineConfiguration::new() };
    let kernel_url = file_url(kernel)?;
    let initrd_url = file_url(initrd)?;
    let loader =
        unsafe { VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url) };
    unsafe {
        loader.setInitialRamdiskURL(Some(&initrd_url));
        loader.setCommandLine(&NSString::from_str(
            "console=hvc0 reboot=k panic=1 init=/init",
        ));
        config.setBootLoader(Some(&loader));
        config.setPlatform(&VZGenericPlatformConfiguration::new());
    }
    let cpu = {
        let min = unsafe { VZVirtualMachineConfiguration::minimumAllowedCPUCount() };
        let max = unsafe { VZVirtualMachineConfiguration::maximumAllowedCPUCount() };
        2.clamp(min, max)
    };
    let memory = {
        let min = unsafe { VZVirtualMachineConfiguration::minimumAllowedMemorySize() };
        let max = unsafe { VZVirtualMachineConfiguration::maximumAllowedMemorySize() };
        (1024 * 1024 * 1024).clamp(min, max)
    };
    unsafe {
        config.setCPUCount(cpu);
        config.setMemorySize(memory);
    }

    let entropy = unsafe { VZVirtioEntropyDeviceConfiguration::new() };
    let entropy_ref: &VZEntropyDeviceConfiguration = &entropy;
    unsafe { config.setEntropyDevices(&NSArray::from_slice(&[entropy_ref])) };

    let nat = unsafe { VZNATNetworkDeviceAttachment::new() };
    let nic = unsafe { VZVirtioNetworkDeviceConfiguration::new() };
    unsafe { nic.setAttachment(Some(&nat)) };
    let nic_ref: &VZNetworkDeviceConfiguration = &nic;
    unsafe { config.setNetworkDevices(&NSArray::from_slice(&[nic_ref])) };

    let socket = unsafe { VZVirtioSocketDeviceConfiguration::new() };
    let socket_ref: &objc2_virtualization::VZSocketDeviceConfiguration = &socket;
    unsafe { config.setSocketDevices(&NSArray::from_slice(&[socket_ref])) };

    let mut directories = Vec::new();
    for export in exports {
        let host_url = file_url(&export.host)?;
        let shared = unsafe {
            objc2_virtualization::VZSharedDirectory::initWithURL_readOnly(
                objc2_virtualization::VZSharedDirectory::alloc(),
                &host_url,
                false,
            )
        };
        let share = unsafe {
            objc2_virtualization::VZSingleDirectoryShare::initWithDirectory(
                objc2_virtualization::VZSingleDirectoryShare::alloc(),
                &shared,
            )
        };
        let device = unsafe {
            VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &NSString::from_str(export.tag),
            )
        };
        unsafe { device.setShare(Some(&share)) };
        directories.push(device);
    }
    let directory_refs: Vec<&VZDirectorySharingDeviceConfiguration> =
        directories.iter().map(|device| device as _).collect();
    unsafe { config.setDirectorySharingDevices(&NSArray::from_slice(&directory_refs)) };

    let (console_read, console_write) = anon_pipe()?;
    let null = File::open("/dev/null").map_err(io_err)?;
    let stdin = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        NSFileHandle::alloc(),
        null.into_raw_fd(),
        true,
    );
    let stdout = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        NSFileHandle::alloc(),
        console_write.into_raw_fd(),
        true,
    );
    let attachment = unsafe {
        VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
            VZFileHandleSerialPortAttachment::alloc(),
            Some(&stdin),
            Some(&stdout),
        )
    };
    let port = unsafe { VZVirtioConsoleDeviceSerialPortConfiguration::new() };
    unsafe { port.setAttachment(Some(&attachment)) };
    let port_ref: &VZSerialPortConfiguration = &port;
    unsafe { config.setSerialPorts(&NSArray::from_slice(&[port_ref])) };

    unsafe { config.validateWithError() }
        .map_err(|err| fail(ErrorCode::Prerequisite, ns_error_text(&err)))?;
    Ok((console_read, config))
}

impl Guest {
    fn stop(self) {
        let vm_ptr = Retained::as_ptr(&self.vm) as usize;
        let _ = wait_on_queue(&self.queue, Duration::from_secs(10), move |done| {
            let vm = unsafe { &*(vm_ptr as *const VZVirtualMachine) };
            let once = StdMutex::new(Some(done));
            unsafe {
                vm.stopWithCompletionHandler(&RcBlock::new(move |_err: *mut NSError| {
                    if let Some(done) = once
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .take()
                    {
                        done(Ok(()));
                    }
                }));
            }
        });
    }
}

fn spawn_console(fd: OwnedFd) -> JoinHandle<()> {
    thread::Builder::new()
        .name("oci-builder-console".into())
        .spawn(move || {
            let mut file = File::from(fd);
            let mut buf = [0u8; 4096];
            loop {
                match file.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut err = io::stderr().lock();
                        let _ = err.write_all(&buf[..n]);
                        let _ = err.flush();
                    }
                }
            }
        })
        .expect("console thread")
}

fn anon_pipe() -> Result<(OwnedFd, OwnedFd), Error> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io_err(io::Error::last_os_error()));
    }
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

fn prepare_fd(fd: c_int) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
        let fd_flags = libc::fcntl(fd, libc::F_GETFD);
        if fd_flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC);
        }
    }
}

fn file_url(path: &Path) -> Result<Retained<NSURL>, Error> {
    let text = path.to_str().ok_or_else(|| {
        fail(
            ErrorCode::InvalidArgument,
            format!("path is not valid Unicode: {}", path.display()),
        )
    })?;
    Ok(NSURL::fileURLWithPath(&NSString::from_str(text)))
}

fn virtualization_supported() -> bool {
    unsafe { VZVirtualMachine::isSupported() }
}

fn ns_result(err: *mut NSError) -> Result<(), String> {
    if err.is_null() {
        Ok(())
    } else {
        Err(ns_message(err))
    }
}

fn ns_message(err: *mut NSError) -> String {
    if err.is_null() {
        "virtual machine failed".to_string()
    } else {
        ns_error_text(unsafe { &*err })
    }
}

fn ns_error_text(err: &NSError) -> String {
    err.localizedDescription().to_string()
}

const EMBEDDED_KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rob-guest-vmlinuz"));
const EMBEDDED_INITRD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rob-guest-initramfs"));

fn locate_artifacts() -> Result<(PathBuf, PathBuf), Error> {
    match (env::var("ROB_GUEST_KERNEL"), env::var("ROB_GUEST_INITRD")) {
        (Ok(kernel), Ok(initrd)) => {
            return require_pair(PathBuf::from(kernel), PathBuf::from(initrd));
        }
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
            return Err(fail(
                ErrorCode::Prerequisite,
                "set both ROB_GUEST_KERNEL and ROB_GUEST_INITRD",
            ));
        }
        (Err(_), Err(_)) => {}
    }
    if !EMBEDDED_KERNEL.is_empty() && !EMBEDDED_INITRD.is_empty() {
        return materialize_embedded();
    }
    let mut tried = Vec::new();
    let mut candidates = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("guest/out")];
    if let Ok(cwd) = env::current_dir() {
        let mut dir = cwd;
        for _ in 0..6 {
            candidates.push(dir.join("guest/out"));
            if !dir.pop() {
                break;
            }
        }
    }
    if let Ok(exe) = env::current_exe() {
        let mut dir = exe;
        for _ in 0..8 {
            if !dir.pop() {
                break;
            }
            candidates.push(dir.join("guest/out"));
        }
    }
    for candidate in candidates {
        tried.push(candidate.display().to_string());
        if let Ok(pair) = require_pair(candidate.join("vmlinuz"), candidate.join("initramfs")) {
            return Ok(pair);
        }
    }
    Err(Error::new(
        ErrorCode::Prerequisite,
        "Linux guest kernel and initramfs were not found",
        format!(
            "looked for guest/out under {}. Rebuild with guest/out present to embed the images, or set ROB_GUEST_KERNEL and ROB_GUEST_INITRD.",
            tried.join(", ")
        ),
    ))
}

fn materialize_embedded() -> Result<(PathBuf, PathBuf), Error> {
    let dir = guest_cache_dir().join(format!(
        "{}-{}",
        EMBEDDED_KERNEL.len(),
        EMBEDDED_INITRD.len()
    ));
    let kernel = dir.join("vmlinuz");
    let initrd = dir.join("initramfs");
    write_embedded(&kernel, EMBEDDED_KERNEL)?;
    write_embedded(&initrd, EMBEDDED_INITRD)?;
    Ok((kernel, initrd))
}

fn guest_cache_dir() -> PathBuf {
    match env::var("HOME") {
        Ok(home) if !home.is_empty() => PathBuf::from(home).join("Library/Caches/oci-builder"),
        // A per-uid directory, not a shared /tmp name another account can pre-create.
        _ => env::temp_dir().join(format!("oci-builder-guest-{}", unsafe { libc::getuid() })),
    }
}

fn write_embedded(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Ok(existing) = std::fs::read(path) {
        if existing == bytes {
            return Ok(());
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            fail(
                ErrorCode::Internal,
                format!("creating {}: {err}", parent.display()),
            )
        })?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let tmp = path.with_extension("partial");
    std::fs::write(&tmp, bytes).map_err(|err| {
        fail(
            ErrorCode::Internal,
            format!("writing {}: {err}", tmp.display()),
        )
    })?;
    std::fs::rename(&tmp, path).map_err(|err| {
        fail(
            ErrorCode::Internal,
            format!("renaming {} to {}: {err}", tmp.display(), path.display()),
        )
    })
}

fn require_pair(kernel: PathBuf, initrd: PathBuf) -> Result<(PathBuf, PathBuf), Error> {
    if kernel.is_file() && initrd.is_file() {
        Ok((kernel, initrd))
    } else {
        Err(fail(
            ErrorCode::Prerequisite,
            format!(
                "missing guest kernel {} or initramfs {}",
                kernel.display(),
                initrd.display()
            ),
        ))
    }
}

fn io_err(err: io::Error) -> Error {
    fail(ErrorCode::Internal, format!("guest socket: {err}"))
}

fn fail(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message, "")
}
