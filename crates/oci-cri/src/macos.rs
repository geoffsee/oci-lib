// SPDX-License-Identifier: Apache-2.0

//! macOS host that boots the Linux CRI guest and proxies unix→vsock.
//!
//! Each accepted host unix connection becomes one vsock dial to the guest
//! agent. The guest writes [`GUEST_BANNER`] then forwards bytes to its local
//! CRI gRPC server. Streaming (Exec/Attach) URLs that point at guest
//! localhost are not rewritten yet — use CNI-disabled sandboxes for the MVP.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};

use dispatch2::{DispatchQueue, DispatchRetained};
use objc2::rc::Retained;
use objc2_virtualization::VZVirtualMachine;
use oci_util::vm::{
    BootedVm, Export, GUEST_ROOT, GUEST_RUNROOT, TAG_ROOT, TAG_RUNROOT, VmError, VmErrorKind,
    add_dir, boot_vm, connect_guest_vsock, lines_from_attestation, materialize_embedded,
    stop_virtual_machine, virtualization_supported, wait_readable,
};

use crate::config::Config;
use crate::error::{Error, ErrorCode};
use crate::guest_config::GUEST;
use crate::proto::{GUEST_BANNER, VSOCK_PORT};

struct Shared {
    jobs: std::sync::mpsc::Sender<Job>,
    join: Option<JoinHandle<()>>,
}

enum Job {
    Connect {
        reply: std::sync::mpsc::Sender<Result<(File, File), Error>>,
    },
    Stop {
        reply: std::sync::mpsc::Sender<Result<(), Error>>,
    },
}

struct Guest {
    vm: Retained<VZVirtualMachine>,
    queue: DispatchRetained<DispatchQueue>,
    _console: JoinHandle<()>,
}

static SESSION: Mutex<Option<Shared>> = Mutex::new(None);

/// Boot the guest and start proxying `config.socket` onto vsock.
pub fn serve(config: Config) -> Result<(), Error> {
    config.validate()?;
    open(&config)?;
    let result = proxy_loop(&config);
    let _ = shutdown();
    result
}

/// Report whether this Mac can boot the embedded CRI guest.
pub fn diagnose(_config: &Config) -> Result<String, Error> {
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
    lines.push(
        "[note] Exec/Attach streaming URLs are not host-rewritten yet; CNI is disabled in the guest"
            .into(),
    );
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

fn open(config: &Config) -> Result<(), Error> {
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
    std::fs::create_dir_all(&config.root).map_err(io_err)?;
    std::fs::create_dir_all(&config.state_root).map_err(io_err)?;
    let exports = plan_exports(config)?;
    let (kernel, initrd) = locate_artifacts()?;
    let mut slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    if slot.is_some() {
        return Err(fail(ErrorCode::State, "CRI guest is already open"));
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let join = thread::Builder::new()
        .name(GUEST.thread_name.into())
        .spawn(move || worker(rx, kernel, initrd, exports))
        .map_err(|err| fail(ErrorCode::Internal, format!("guest thread: {err}")))?;
    *slot = Some(Shared {
        jobs: tx,
        join: Some(join),
    });
    drop(slot);
    // Wait until the guest agent accepts a vsock and returns the banner.
    let (mut read, _write) = connect()?;
    expect_banner(&mut read)?;
    Ok(())
}

fn shutdown() -> Result<(), Error> {
    let mut slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    let Some(mut shared) = slot.take() else {
        return Ok(());
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

fn proxy_loop(config: &Config) -> Result<(), Error> {
    if let Some(parent) = config.socket.parent() {
        std::fs::create_dir_all(parent).map_err(io_err)?;
    }
    let _ = std::fs::remove_file(&config.socket);
    let listener = UnixListener::bind(&config.socket).map_err(io_err)?;
    eprintln!(
        "{}: listening on {} (macOS guest proxy)",
        config.runtime_name,
        config.socket.display()
    );
    loop {
        let (client, _) = listener.accept().map_err(io_err)?;
        match connect() {
            Ok((mut read, write)) => {
                if let Err(err) = expect_banner(&mut read) {
                    eprintln!("oci-cri: guest banner: {err}");
                    continue;
                }
                spawn_proxy(client, read, write);
            }
            Err(err) => {
                eprintln!("oci-cri: vsock connect: {err}");
            }
        }
    }
}

fn spawn_proxy(client: UnixStream, vsock_read: File, vsock_write: File) {
    let client_read = match client.try_clone() {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("oci-cri: clone client: {err}");
            return;
        }
    };
    thread::spawn(move || {
        let mut client = client;
        let mut vsock = vsock_read;
        let _ = io::copy(&mut vsock, &mut client);
    });
    thread::spawn(move || {
        let mut client = client_read;
        let mut vsock = vsock_write;
        let _ = io::copy(&mut client, &mut vsock);
    });
}

fn connect() -> Result<(File, File), Error> {
    let slot = SESSION.lock().unwrap_or_else(|poison| poison.into_inner());
    let shared = slot
        .as_ref()
        .ok_or_else(|| fail(ErrorCode::State, "CRI guest is not open"))?;
    let (tx, rx) = std::sync::mpsc::channel();
    shared
        .jobs
        .send(Job::Connect { reply: tx })
        .map_err(|_| fail(ErrorCode::Internal, "guest thread has stopped"))?;
    drop(slot);
    rx.recv()
        .map_err(|_| fail(ErrorCode::Internal, "guest thread dropped connect"))?
}

fn expect_banner(read: &mut File) -> Result<(), Error> {
    wait_readable(read, GUEST.handshake_timeout).map_err(|err| {
        Error::new(
            ErrorCode::Prerequisite,
            "guest protocol handshake failed",
            format!(
                "host expects banner {:?}; the embedded guest did not respond: {err}. Rebuild with `cargo xtask guest oci-cri`.",
                String::from_utf8_lossy(GUEST_BANNER)
            ),
        )
    })?;
    let mut buf = [0u8; GUEST_BANNER.len()];
    read.read_exact(&mut buf).map_err(|err| {
        Error::new(
            ErrorCode::Prerequisite,
            "guest protocol handshake failed",
            format!("reading guest banner: {err}"),
        )
    })?;
    if &buf != GUEST_BANNER {
        return Err(Error::new(
            ErrorCode::Prerequisite,
            "guest protocol mismatch",
            format!(
                "expected banner {:?}, got {:?}",
                String::from_utf8_lossy(GUEST_BANNER),
                String::from_utf8_lossy(&buf)
            ),
        ));
    }
    Ok(())
}

fn worker(
    rx: std::sync::mpsc::Receiver<Job>,
    kernel: PathBuf,
    initrd: PathBuf,
    exports: Vec<Export>,
) {
    let mut guest: Option<Guest> = None;
    while let Ok(job) = rx.recv() {
        match job {
            Job::Connect { reply } => {
                let result = ensure_guest(&mut guest, &kernel, &initrd, &exports).and_then(dial);
                let _ = reply.send(result);
            }
            Job::Stop { reply } => {
                if let Some(guest) = guest.take() {
                    guest.stop();
                }
                let _ = reply.send(Ok(()));
                break;
            }
        }
    }
}

fn ensure_guest<'a>(
    guest: &'a mut Option<Guest>,
    kernel: &Path,
    initrd: &Path,
    exports: &[Export],
) -> Result<&'a Guest, Error> {
    if guest.is_none() {
        let booted = boot(kernel, initrd, exports)?;
        *guest = Some(booted);
    }
    Ok(guest.as_ref().expect("guest just set"))
}

fn dial(guest: &Guest) -> Result<(File, File), Error> {
    connect_guest_vsock(&guest.vm, &guest.queue, VSOCK_PORT, GUEST.boot_timeout).map_err(map_vm)
}

fn boot(kernel: &Path, initrd: &Path, exports: &[Export]) -> Result<Guest, Error> {
    let booted: BootedVm = boot_vm(&GUEST, kernel, initrd, exports).map_err(map_vm)?;
    Ok(Guest {
        vm: booted.vm,
        queue: booted.queue,
        _console: booted.console,
    })
}

impl Guest {
    fn stop(self) {
        stop_virtual_machine(self.vm, &self.queue);
    }
}

fn plan_exports(config: &Config) -> Result<Vec<Export>, Error> {
    let mut exports = Vec::new();
    add_dir(&mut exports, TAG_ROOT, GUEST_ROOT, &config.root, false)
        .map_err(|err| fail(ErrorCode::InvalidArgument, err))?;
    add_dir(
        &mut exports,
        TAG_RUNROOT,
        GUEST_RUNROOT,
        &config.state_root,
        false,
    )
    .map_err(|err| fail(ErrorCode::InvalidArgument, err))?;
    Ok(exports)
}

const EMBEDDED_KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rok-guest-vmlinuz.zst"));
const EMBEDDED_INITRD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rok-guest-initramfs.zst"));
const EMBEDDED_ATTESTATION: &str =
    include_str!(concat!(env!("OUT_DIR"), "/rok-guest-attestation.json"));

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
    fail(ErrorCode::Internal, err.to_string())
}

fn fail(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message, "")
}
