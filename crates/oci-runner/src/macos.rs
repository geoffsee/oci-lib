// SPDX-License-Identifier: Apache-2.0

//! macOS host for the Linux libcontainer engine.
//!
//! `startup` does not boot anything, so `--help` stays local. The guest starts
//! on the first run: virtiofs devices are fixed for the life of the VM, and
//! the rootfs directory is only known then.

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

use crate::proto::{
    GuestFrame, HostFrame, Run, STDERR, VSOCK_PORT, read_guest_frame, write_host_frame,
};
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

use crate::OutputFn;
use crate::error::{Error, ErrorCode};
use crate::request::PreparedRun;
use crate::shares::{Export, GUEST_ROOTFS, export_rootfs};

const BOOT_TIMEOUT: Duration = Duration::from_secs(30);

struct Shared {
    jobs: std::sync::mpsc::Sender<Job>,
    join: Option<JoinHandle<()>>,
}

enum Job {
    Ensure {
        export: Export,
        reply: std::sync::mpsc::Sender<Result<Export, Error>>,
    },
    Run {
        frame: HostFrame,
        on_output: OutputFn,
        reply: std::sync::mpsc::Sender<Result<i32, Error>>,
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
    export: Export,
}

static SESSION: Mutex<Option<Shared>> = Mutex::new(None);

pub(crate) fn open() -> Result<(), Error> {
    if !virtualization_supported() {
        return Err(fail(
            ErrorCode::Prerequisite,
            "Apple Virtualization.framework is not available on this Mac",
        ));
    }
    if !crate::entitlement::present() {
        return Err(crate::entitlement::missing());
    }
    let (kernel, initrd) = locate_artifacts()?;
    let mut slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    if slot.is_some() {
        return Err(fail(ErrorCode::State, "runtime is already open"));
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let write = Arc::new(Mutex::new(None));
    let join = thread::Builder::new()
        .name("oci-runner-guest".into())
        .spawn(move || worker(rx, write, kernel, initrd))
        .map_err(|err| fail(ErrorCode::Internal, format!("guest thread: {err}")))?;
    *slot = Some(Shared {
        jobs: tx,
        join: Some(join),
    });
    Ok(())
}

pub(crate) fn run(prepared: &PreparedRun, on_output: Option<OutputFn>) -> Result<i32, Error> {
    let export =
        export_rootfs(&prepared.rootfs).map_err(|err| fail(ErrorCode::InvalidArgument, err))?;
    let _export = with_session(|shared| call_ensure(shared, export))?;
    let frame = HostFrame::Run(Run {
        rootfs: GUEST_ROOTFS.to_string(),
        argv: prepared.argv.clone(),
        env: prepared.env.clone(),
        cwd: prepared.cwd.clone(),
        hostname: prepared.hostname.clone(),
        state_root: String::new(),
        isolate_network: prepared.isolate_network,
    });
    let on_output = on_output.unwrap_or_else(|| Arc::new(write_stdio));
    rpc(frame, on_output)
}

pub(crate) fn shutdown() -> Result<(), Error> {
    let mut slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    let Some(mut shared) = slot.take() else {
        return Err(fail(ErrorCode::State, "runtime is not open"));
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
    if crate::entitlement::present() {
        lines.push("[ok] com.apple.security.virtualization entitlement".to_string());
    } else {
        blocked = true;
        let err = crate::entitlement::missing();
        lines.push(format!("[fail] {}", err.message()));
        lines.push(err.detail().to_string());
    }
    match locate_artifacts() {
        Ok((kernel, initrd)) => {
            lines.push(format!("[ok] guest kernel {}", kernel.display()));
            lines.push(format!("[ok] guest initramfs {}", initrd.display()));
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

fn write_stdio(stream: u8, data: &[u8]) {
    if stream == STDERR {
        let mut err = io::stderr().lock();
        let _ = err.write_all(data);
        let _ = err.flush();
    } else {
        let mut out = io::stdout().lock();
        let _ = out.write_all(data);
        let _ = out.flush();
    }
}

fn with_session<T>(body: impl FnOnce(&Shared) -> Result<T, Error>) -> Result<T, Error> {
    let slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    let shared = slot
        .as_ref()
        .ok_or_else(|| fail(ErrorCode::State, "runtime is not open"))?;
    body(shared)
}

fn call_ensure(shared: &Shared, export: Export) -> Result<Export, Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    shared
        .jobs
        .send(Job::Ensure { export, reply: tx })
        .map_err(|_| fail(ErrorCode::Internal, "guest thread has stopped"))?;
    rx.recv()
        .map_err(|_| fail(ErrorCode::Internal, "guest thread dropped ensure"))?
}

fn rpc(frame: HostFrame, on_output: OutputFn) -> Result<i32, Error> {
    let slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    let shared = slot
        .as_ref()
        .ok_or_else(|| fail(ErrorCode::State, "runtime is not open"))?;
    let (tx, rx) = std::sync::mpsc::channel();
    shared
        .jobs
        .send(Job::Run {
            frame,
            on_output,
            reply: tx,
        })
        .map_err(|_| fail(ErrorCode::Internal, "guest thread has stopped"))?;
    drop(slot);
    rx.recv()
        .map_err(|_| fail(ErrorCode::Internal, "guest thread dropped the call"))?
}

fn worker(
    rx: std::sync::mpsc::Receiver<Job>,
    write: Arc<Mutex<Option<File>>>,
    kernel: PathBuf,
    initrd: PathBuf,
) {
    let mut guest: Option<Guest> = None;
    while let Ok(job) = rx.recv() {
        match job {
            Job::Ensure { export, reply } => {
                let result = ensure_guest(&mut guest, export, &write, &kernel, &initrd);
                let _ = reply.send(result);
            }
            Job::Run {
                frame,
                on_output,
                reply,
            } => {
                let result = match guest.as_mut() {
                    Some(guest) => exchange(&mut guest.read, &write, &frame, &on_output),
                    None => Err(fail(ErrorCode::Internal, "guest is not running")),
                };
                let _ = reply.send(result);
            }
            Job::Stop { reply } => {
                if let Some(guest) = guest.as_mut() {
                    let sink: OutputFn = Arc::new(|_: u8, _: &[u8]| {});
                    let _ = exchange(&mut guest.read, &write, &HostFrame::Shutdown, &sink);
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
    export: Export,
    write: &Arc<Mutex<Option<File>>>,
    kernel: &Path,
    initrd: &Path,
) -> Result<Export, Error> {
    if let Some(existing) = guest.as_ref() {
        if existing.export.host == export.host {
            return Ok(existing.export.clone());
        }
        return Err(fail(
            ErrorCode::InvalidArgument,
            format!(
                "{} is not the rootfs the running guest can see; shutdown before using a new directory",
                export.host.display()
            ),
        ));
    }
    let started = boot(kernel, initrd, &export, write)?;
    let booted = started.export.clone();
    *guest = Some(started);
    Ok(booted)
}

fn exchange(
    read: &mut File,
    write: &Arc<Mutex<Option<File>>>,
    frame: &HostFrame,
    on_output: &OutputFn,
) -> Result<i32, Error> {
    write_locked(write, frame)?;
    loop {
        let guest = read_guest_frame(read).map_err(io_err)?;
        match guest {
            GuestFrame::Output { stream, data } => on_output(stream, &data),
            GuestFrame::Status { code } => return Ok(code),
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

fn boot(
    kernel: &Path,
    initrd: &Path,
    export: &Export,
    write: &Arc<Mutex<Option<File>>>,
) -> Result<Guest, Error> {
    let queue = DispatchQueue::new("oci-runner.vm", DispatchQueueAttr::SERIAL);
    let (console_read, config) = vm_config(kernel, initrd, export)?;
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
        export: export.clone(),
    })
}

fn connect_vsock(vm_ptr: usize, queue: &DispatchQueue) -> Result<c_int, Error> {
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
    export: &Export,
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
    let device_ref: &VZDirectorySharingDeviceConfiguration = &device;
    unsafe { config.setDirectorySharingDevices(&NSArray::from_slice(&[device_ref])) };

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
        .name("oci-runner-console".into())
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

const EMBEDDED_KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ror-guest-vmlinuz.zst"));
const EMBEDDED_INITRD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ror-guest-initramfs.zst"));

/// The guest always boots from the images embedded at build time. They are
/// written to the cache directory because the boot loader takes file URLs.
fn locate_artifacts() -> Result<(PathBuf, PathBuf), Error> {
    materialize_embedded()
}

fn materialize_embedded() -> Result<(PathBuf, PathBuf), Error> {
    let dir = guest_cache_dir().join(format!(
        "{}-{}",
        EMBEDDED_KERNEL.len(),
        EMBEDDED_INITRD.len()
    ));
    let kernel = dir.join("vmlinuz");
    let initrd = dir.join("initramfs");
    write_embedded(&kernel, &decompress(EMBEDDED_KERNEL)?)?;
    write_embedded(&initrd, &decompress(EMBEDDED_INITRD)?)?;
    Ok((kernel, initrd))
}

fn decompress(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    zstd::decode_all(bytes).map_err(|err| {
        fail(
            ErrorCode::Internal,
            format!("decompressing the embedded guest: {err}"),
        )
    })
}

fn guest_cache_dir() -> PathBuf {
    match env::var("HOME") {
        Ok(home) if !home.is_empty() => PathBuf::from(home).join("Library/Caches/oci-runner"),
        _ => env::temp_dir().join(format!("oci-runner-guest-{}", unsafe { libc::getuid() })),
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

fn io_err(err: io::Error) -> Error {
    fail(ErrorCode::Internal, format!("guest socket: {err}"))
}

fn fail(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message, "")
}
