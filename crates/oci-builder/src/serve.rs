// SPDX-License-Identifier: Apache-2.0

//! Virtio-vsock agent. The macOS host boots this binary as `/init`'s last exec.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use oci_builder::proto::{
    Build, GuestFrame, HostFrame, Init, Push, VSOCK_PORT, read_host_frame, write_guest_frame,
};

use oci_builder::{
    BuildRequest, Builder, CancelToken, Config, Error, ErrorCode, ImageFormat, ImageInfo,
    Isolation, LogLevel, LogRecord, LogStream, PullPolicy, PushRequest, StorageDriver,
};

struct Tokens {
    live: HashMap<u64, CancelToken>,
    fired: HashSet<u64>,
}

pub fn engine_serve() -> Result<(), Error> {
    let listener = vsock_listen(VSOCK_PORT)
        .map_err(|err| Error::new(ErrorCode::Prerequisite, format!("vsock listen: {err}"), ""))?;
    let client = vsock_accept(&listener)
        .map_err(|err| Error::new(ErrorCode::Internal, format!("vsock accept: {err}"), ""))?;
    drop(listener);
    let read = Arc::new(Mutex::new(client.try_clone().map_err(|err| {
        Error::new(ErrorCode::Internal, format!("vsock clone: {err}"), "")
    })?));
    let write = Arc::new(Mutex::new(client));
    let tokens = Arc::new(Mutex::new(Tokens {
        live: HashMap::new(),
        fired: HashSet::new(),
    }));
    let (tx, rx) = std::sync::mpsc::channel();
    let tokens_reader = Arc::clone(&tokens);
    let read_thread = Arc::clone(&read);
    thread::Builder::new()
        .name("oci-builder-vsock".into())
        .spawn(move || reader(read_thread, tokens_reader, tx))
        .map_err(|err| Error::new(ErrorCode::Internal, format!("vsock reader: {err}"), ""))?;

    let mut builder: Option<Builder> = None;
    while let Ok(frame) = rx.recv() {
        match frame {
            HostFrame::Init(init) => {
                let response = match open_builder(&mut builder, &init) {
                    Ok(()) => empty_result(),
                    Err(err) => error_frame(&err),
                };
                write_frame(&write, &response)?;
            }
            HostFrame::Build(build) => {
                let response = match run_build(&builder, &build, &tokens, &write) {
                    Ok(info) => GuestFrame::Result {
                        image_id: info.image_id,
                        digest: info.digest.unwrap_or_default(),
                        reference: info.reference.unwrap_or_default(),
                    },
                    Err(err) => error_frame(&err),
                };
                write_frame(&write, &response)?;
            }
            HostFrame::Tag { image, new_name } => {
                let response = match builder.as_ref() {
                    Some(builder) => match builder.tag(&image, &new_name) {
                        Ok(()) => empty_result(),
                        Err(err) => error_frame(&err),
                    },
                    None => error_frame(&Error::new(ErrorCode::State, "store is not open", "")),
                };
                write_frame(&write, &response)?;
            }
            HostFrame::Push(push) => {
                let response = match run_push(&builder, &push, &tokens, &write) {
                    Ok(info) => GuestFrame::Result {
                        image_id: info.image_id,
                        digest: info.digest.unwrap_or_default(),
                        reference: info.reference.unwrap_or_default(),
                    },
                    Err(err) => error_frame(&err),
                };
                write_frame(&write, &response)?;
            }
            HostFrame::Diagnose => {
                let response = match Builder::diagnose() {
                    Ok(report) => GuestFrame::Result {
                        image_id: report,
                        digest: String::new(),
                        reference: String::new(),
                    },
                    Err(err) => error_frame(&err),
                };
                write_frame(&write, &response)?;
            }
            HostFrame::Cancel { token } => note_cancel(&tokens, token),
            HostFrame::Shutdown => {
                let response = match builder.take() {
                    Some(builder) => match builder.shutdown() {
                        Ok(()) => empty_result(),
                        Err(err) => error_frame(&err),
                    },
                    None => empty_result(),
                };
                // The host stops the VM as soon as this reply arrives. Unmount
                // the graph image first so the next boot does not see a torn
                // ext2 filesystem.
                release_guest_store();
                write_frame(&write, &response)?;
                break;
            }
        }
    }
    Ok(())
}

fn reader(
    read: Arc<Mutex<File>>,
    tokens: Arc<Mutex<Tokens>>,
    tx: std::sync::mpsc::Sender<HostFrame>,
) {
    loop {
        let frame = {
            let mut file = read.lock().unwrap_or_else(|poison| poison.into_inner());
            match read_host_frame(&mut *file) {
                Ok(frame) => frame,
                Err(_) => break,
            }
        };
        if let HostFrame::Cancel { token } = frame {
            note_cancel(&tokens, token);
            continue;
        }
        if tx.send(frame).is_err() {
            break;
        }
    }
}

fn note_cancel(tokens: &Mutex<Tokens>, token: u64) {
    let mut guard = tokens.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(live) = guard.live.get(&token) {
        live.cancel();
    } else {
        guard.fired.insert(token);
    }
}

fn arm(tokens: &Mutex<Tokens>, remote: u64) -> Result<Option<CancelToken>, Error> {
    if remote == 0 {
        return Ok(None);
    }
    let token = CancelToken::new()?;
    let mut guard = tokens.lock().unwrap_or_else(|poison| poison.into_inner());
    if guard.fired.remove(&remote) {
        token.cancel();
    }
    guard.live.insert(remote, token.clone());
    Ok(Some(token))
}

fn disarm(tokens: &Mutex<Tokens>, remote: u64) {
    if remote == 0 {
        return;
    }
    tokens
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .live
        .remove(&remote);
}

fn open_builder(slot: &mut Option<Builder>, init: &Init) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::new(ErrorCode::State, "store is already open", ""));
    }
    *slot = Some(Builder::open(config_from_init(init)?)?);
    Ok(())
}

fn config_from_init(init: &Init) -> Result<Config, Error> {
    Ok(Config {
        storage_root: optional_path(&init.storage_root),
        run_root: optional_path(&init.run_root),
        storage_driver: match init.storage_driver.as_str() {
            "" => None,
            "vfs" => Some(StorageDriver::Vfs),
            "overlay" => Some(StorageDriver::Overlay),
            other => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("unknown storage driver {other}"),
                    "",
                ));
            }
        },
        storage_opts: init.storage_opts.clone(),
        registries_conf: optional_path(&init.registries_conf),
        signature_policy: optional_path(&init.signature_policy),
        auth_file: optional_path(&init.auth_file),
        insecure: init.insecure,
        log_level: match init.log_level.as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "" | "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            other => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("unknown log level {other}"),
                    "",
                ));
            }
        },
        signing_key: None,
        signing_cert_chain: Vec::new(),
        trust_policy: None,
        trust_anchors: std::collections::BTreeMap::new(),
    })
}

fn run_build(
    builder: &Option<Builder>,
    build: &Build,
    tokens: &Mutex<Tokens>,
    write: &Arc<Mutex<File>>,
) -> Result<ImageInfo, Error> {
    let Some(builder) = builder else {
        return Err(Error::new(ErrorCode::State, "store is not open", ""));
    };
    let token = arm(tokens, build.cancel_token)?;
    let write = Arc::clone(write);
    let mut request = BuildRequest::new(&build.dockerfile, &build.context_dir);
    request.tag = optional_string(&build.tag);
    request.target = optional_string(&build.target);
    request.isolation = parse_isolation(&build.isolation)?;
    request.format = parse_format(&build.format)?;
    request.pull = parse_pull(&build.pull)?;
    request.os = optional_string(&build.os);
    request.arch = optional_string(&build.arch);
    request.variant = optional_string(&build.variant);
    request.build_args = build.build_args.iter().cloned().collect();
    request.labels = build.labels.iter().cloned().collect();
    request.layers = build.layers != 0;
    request.excludes = build.excludes.clone();
    request.no_cache = build.no_cache;
    request.squash = build.squash;
    request.quiet = build.quiet;
    request.cancel = token;
    request.on_log = Some(Arc::new(move |record: LogRecord| {
        let _ = write_frame(
            &write,
            &GuestFrame::Log {
                stream: log_code(&record),
                message: record.message,
            },
        );
    }));
    let result = builder.build(request);
    disarm(tokens, build.cancel_token);
    result
}

fn run_push(
    builder: &Option<Builder>,
    push: &Push,
    tokens: &Mutex<Tokens>,
    write: &Arc<Mutex<File>>,
) -> Result<ImageInfo, Error> {
    let Some(builder) = builder else {
        return Err(Error::new(ErrorCode::State, "store is not open", ""));
    };
    let token = arm(tokens, push.cancel_token)?;
    let write = Arc::clone(write);
    let mut request = PushRequest::new(&push.image, &push.destination);
    request.username = push.username.clone();
    request.password = push.password.clone();
    request.format = if push.format.is_empty() {
        None
    } else {
        Some(parse_format(&push.format)?)
    };
    request.insecure = push.insecure;
    request.cancel = token;
    request.on_log = Some(Arc::new(move |record: LogRecord| {
        let _ = write_frame(
            &write,
            &GuestFrame::Log {
                stream: log_code(&record),
                message: record.message,
            },
        );
    }));
    let result = builder.push(request);
    disarm(tokens, push.cancel_token);
    result
}

fn log_code(record: &LogRecord) -> u8 {
    match record.stream {
        LogStream::Progress => oci_builder::proto::LOG_PROGRESS,
        LogStream::Info => oci_builder::proto::LOG_INFO,
        LogStream::Warn => oci_builder::proto::LOG_WARN,
        LogStream::Error => oci_builder::proto::LOG_ERROR,
    }
}

fn parse_isolation(value: &str) -> Result<Isolation, Error> {
    match value {
        "" | "default" => Ok(Isolation::Default),
        "oci" => Ok(Isolation::Oci),
        "rootless" => Ok(Isolation::Rootless),
        "chroot" => Ok(Isolation::Chroot),
        other => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown isolation {other}"),
            "",
        )),
    }
}

fn parse_format(value: &str) -> Result<ImageFormat, Error> {
    match value {
        "" | "oci" => Ok(ImageFormat::Oci),
        "docker" => Ok(ImageFormat::Docker),
        other => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown image format {other}"),
            "",
        )),
    }
}

fn parse_pull(value: &str) -> Result<PullPolicy, Error> {
    match value {
        "" | "missing" => Ok(PullPolicy::IfMissing),
        "always" => Ok(PullPolicy::Always),
        "ifnewer" => Ok(PullPolicy::IfNewer),
        "never" => Ok(PullPolicy::Never),
        other => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown pull policy {other}"),
            "",
        )),
    }
}

fn optional_path(value: &str) -> Option<PathBuf> {
    if value.is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn optional_string(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn empty_result() -> GuestFrame {
    GuestFrame::Result {
        image_id: String::new(),
        digest: String::new(),
        reference: String::new(),
    }
}

fn error_frame(err: &Error) -> GuestFrame {
    GuestFrame::Error {
        code: err.code().as_exit(),
        message: err.message().to_string(),
        detail: err.detail().to_string(),
    }
}

fn release_guest_store() {
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mounted = mounts
        .lines()
        .any(|line| line.split_whitespace().nth(1) == Some("/mnt/root"));
    if !mounted {
        return;
    }
    let _ = std::process::Command::new("sync").status();
    for _ in 0..20 {
        let ok = std::process::Command::new("umount")
            .arg("/mnt/root")
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if ok {
            return;
        }
        thread::sleep(std::time::Duration::from_millis(50));
    }
    eprintln!("oci-builder: umount /mnt/root failed");
}

fn write_frame(write: &Mutex<File>, frame: &GuestFrame) -> Result<(), Error> {
    let mut file = write.lock().unwrap_or_else(|poison| poison.into_inner());
    write_guest_frame(&mut *file, frame)
        .map_err(|err| Error::new(ErrorCode::Internal, format!("vsock write: {err}"), ""))
}

fn vsock_listen(port: u32) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: libc::VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd.as_raw_fd(), 1) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn vsock_accept(listener: &OwnedFd) -> io::Result<File> {
    let mut addr = unsafe { std::mem::zeroed::<libc::sockaddr_vm>() };
    let mut len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
    let fd = unsafe {
        libc::accept(
            listener.as_raw_fd(),
            &mut addr as *mut libc::sockaddr_vm as *mut libc::sockaddr,
            &mut len,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from(OwnedFd::from_raw_fd(fd)) })
}
