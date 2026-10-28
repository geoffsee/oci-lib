// SPDX-License-Identifier: Apache-2.0

//! macOS host for the Linux libcontainer engine.
//!
//! `startup` does not boot anything, so `--help` stays local. The guest starts
//! on the first run: virtiofs devices are fixed for the life of the VM, and
//! the rootfs directory is only known then.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use dispatch2::DispatchQueue;
use dispatch2::DispatchRetained;
use objc2::rc::Retained;
use objc2_virtualization::VZVirtualMachine;
use oci_util::vm::{
    Export, GUEST_ROOTFS, VmError, VmErrorKind, export_rootfs, lines_from_attestation,
    materialize_embedded, start_vm, stop_virtual_machine, virtualization_supported, wait_readable,
};

use crate::OutputFn;
use crate::error::{Error, ErrorCode};
use crate::guest_config::GUEST;
use crate::proto::{
    GuestFrame, HostFrame, PROTOCOL_VERSION, Run, STDERR, read_guest_frame, write_host_frame,
};
use crate::request::PreparedRun;

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
    if !oci_util::vm::entitlement_present() {
        return Err(map_vm(oci_util::vm::missing_entitlement(
            GUEST.no_self_sign_env,
        )));
    }
    let (kernel, initrd) = locate_artifacts()?;
    let mut slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    if slot.is_some() {
        return Err(fail(ErrorCode::State, "runtime is already open"));
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let write = Arc::new(Mutex::new(None));
    let join = thread::Builder::new()
        .name(GUEST.thread_name.into())
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

fn boot(
    kernel: &Path,
    initrd: &Path,
    export: &Export,
    write: &Arc<Mutex<Option<File>>>,
) -> Result<Guest, Error> {
    let started = start_vm(&GUEST, kernel, initrd, std::slice::from_ref(export)).map_err(map_vm)?;
    *write.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(started.write);
    let mut guest = Guest {
        vm: started.vm,
        queue: started.queue,
        _console: started.console,
        read: started.read,
        export: export.clone(),
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

const EMBEDDED_KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ror-guest-vmlinuz.zst"));
const EMBEDDED_INITRD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ror-guest-initramfs.zst"));
const EMBEDDED_ATTESTATION: &str =
    include_str!(concat!(env!("OUT_DIR"), "/ror-guest-attestation.json"));

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
