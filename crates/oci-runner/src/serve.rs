// SPDX-License-Identifier: Apache-2.0

//! Virtio-vsock agent. The macOS guest runs this binary from `/init`.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

use oci_runner::proto::{
    GuestFrame, HostFrame, PROTOCOL_VERSION, Run, VSOCK_PORT, read_host_frame, write_guest_frame,
};
use oci_runner::{Error, ErrorCode, RunRequest, Runtime};

pub fn engine_serve() -> Result<i32, Error> {
    let listener = vsock_listen(VSOCK_PORT)
        .map_err(|err| Error::new(ErrorCode::Prerequisite, format!("vsock listen: {err}"), ""))?;
    let mut client = vsock_accept(&listener)
        .map_err(|err| Error::new(ErrorCode::Internal, format!("vsock accept: {err}"), ""))?;
    drop(listener);
    negotiate(&mut client)?;
    let mut read = client
        .try_clone()
        .map_err(|err| Error::new(ErrorCode::Internal, format!("vsock clone: {err}"), ""))?;
    let write = Arc::new(Mutex::new(client));
    let runtime = Runtime::open()?;
    let result = serve_loop(&runtime, &mut read, &write);
    let shut = runtime.shutdown();
    match (result, shut) {
        (Ok(code), Ok(())) => Ok(code),
        (Ok(_), Err(err)) => Err(err),
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(shut_err)) => {
            eprintln!("shutdown: {shut_err}");
            Err(err)
        }
    }
}

fn serve_loop(runtime: &Runtime, read: &mut File, write: &Arc<Mutex<File>>) -> Result<i32, Error> {
    loop {
        let frame = read_host_frame(read)
            .map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "guest protocol mismatch",
                    format!(
                        "failed to decode a host frame: {err}; guest protocol version {PROTOCOL_VERSION}"
                    ),
                )
            })?;
        match frame {
            HostFrame::Hello { .. } => {
                write_frame(
                    write,
                    &GuestFrame::Error {
                        code: ErrorCode::InvalidArgument.as_exit(),
                        message: "guest protocol handshake already completed".into(),
                        detail: "the host sent a second handshake".into(),
                    },
                )?;
            }
            HostFrame::Run(run) => {
                let response = match handle_run(runtime, &run, write) {
                    Ok(code) => GuestFrame::Status { code },
                    Err(err) => error_frame(&err),
                };
                write_frame(write, &response)?;
            }
            HostFrame::Shutdown => {
                write_frame(write, &GuestFrame::Status { code: 0 })?;
                return Ok(0);
            }
        }
    }
}

fn negotiate(client: &mut File) -> Result<(), Error> {
    let frame = read_host_frame(client).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            "guest protocol handshake failed",
            format!("could not decode the host handshake: {err}"),
        )
    })?;
    match frame {
        HostFrame::Hello { protocol } if protocol == PROTOCOL_VERSION => write_guest_frame(
            client,
            &GuestFrame::Hello {
                protocol: PROTOCOL_VERSION,
            },
        )
        .map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                "guest protocol handshake failed",
                err.to_string(),
            )
        }),
        HostFrame::Hello { protocol } => {
            let detail = format!(
                "host requested protocol version {protocol}, guest implements {PROTOCOL_VERSION}"
            );
            let _ = write_guest_frame(
                client,
                &GuestFrame::Error {
                    code: ErrorCode::InvalidArgument.as_exit(),
                    message: "guest protocol mismatch".into(),
                    detail: detail.clone(),
                },
            );
            Err(Error::new(
                ErrorCode::InvalidArgument,
                "guest protocol mismatch",
                detail,
            ))
        }
        other => {
            let detail = format!("expected a protocol handshake, received {other:?}");
            let _ = write_guest_frame(
                client,
                &GuestFrame::Error {
                    code: ErrorCode::InvalidArgument.as_exit(),
                    message: "guest protocol handshake required".into(),
                    detail: detail.clone(),
                },
            );
            Err(Error::new(
                ErrorCode::InvalidArgument,
                "guest protocol handshake required",
                detail,
            ))
        }
    }
}

fn handle_run(runtime: &Runtime, run: &Run, write: &Arc<Mutex<File>>) -> Result<i32, Error> {
    let mut request = RunRequest::new(&run.rootfs, run.argv.clone())
        .cwd(run.cwd.clone())
        .hostname(run.hostname.clone())
        .isolate_network(run.isolate_network);
    if !run.state_root.is_empty() {
        request = request.state_root(&run.state_root);
    }
    for entry in &run.env {
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("environment entry {entry} is not KEY=VALUE"),
                "",
            )
        })?;
        request = request.env(key, value);
    }
    let write = Arc::clone(write);
    let on_output = Arc::new(move |stream: u8, data: &[u8]| {
        let frame = GuestFrame::Output {
            stream,
            data: data.to_vec(),
        };
        let _ = write_frame(&write, &frame);
    });
    runtime.run_with(&request, Some(on_output))
}

fn error_frame(err: &Error) -> GuestFrame {
    GuestFrame::Error {
        code: err.code().as_exit(),
        message: err.message().to_string(),
        detail: err.detail().to_string(),
    }
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
