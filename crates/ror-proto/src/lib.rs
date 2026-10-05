// SPDX-License-Identifier: Apache-2.0

//! Frames carried over the virtio socket between a macOS host and the Linux guest.
//!
//! A frame is a little-endian `u32` byte length followed by a body. The first
//! body byte is the message tag. Strings are a `u32` length plus UTF-8 bytes.
//! Output payloads are a `u32` length plus raw bytes.

use std::io::{self, Read, Write};

/// Guest virtio-vsock port the agent listens on. The host connects to it.
pub const VSOCK_PORT: u32 = 5253;

/// Largest accepted body. Larger lengths are rejected before allocation.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// Stdio stream codes. They match the C ABI `ROR_STDOUT` and `ROR_STDERR`.
pub const STDOUT: u8 = 1;
pub const STDERR: u8 = 2;

const HOST_RUN: u8 = 1;
const HOST_SHUTDOWN: u8 = 2;

const GUEST_OUTPUT: u8 = 1;
const GUEST_STATUS: u8 = 2;
const GUEST_ERROR: u8 = 3;

/// Host to guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFrame {
    Run(Run),
    Shutdown,
}

/// One container run. `rootfs` is a guest path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub rootfs: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub hostname: String,
    /// Empty means the guest picks its own state directory.
    pub state_root: String,
    pub isolate_network: bool,
}

/// Guest to host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestFrame {
    Output {
        stream: u8,
        data: Vec<u8>,
    },
    Status {
        code: i32,
    },
    Error {
        code: i32,
        message: String,
        detail: String,
    },
}

pub fn write_host_frame(writer: &mut impl Write, frame: &HostFrame) -> io::Result<()> {
    write_body(writer, &encode_host(frame))
}

pub fn write_guest_frame(writer: &mut impl Write, frame: &GuestFrame) -> io::Result<()> {
    write_body(writer, &encode_guest(frame))
}

pub fn read_host_frame(reader: &mut impl Read) -> io::Result<HostFrame> {
    decode_host(&read_body(reader)?)
}

pub fn read_guest_frame(reader: &mut impl Read) -> io::Result<GuestFrame> {
    decode_guest(&read_body(reader)?)
}

fn write_body(writer: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| invalid("frame is too large"))?;
    if len > MAX_FRAME_LEN {
        return Err(invalid("frame is too large"));
    }
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

fn read_body(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(invalid("frame length exceeds the limit"));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    Ok(body)
}

fn encode_host(frame: &HostFrame) -> Vec<u8> {
    let mut w = Buf::new();
    match frame {
        HostFrame::Run(run) => {
            w.u8(HOST_RUN);
            w.str(&run.rootfs);
            w.strs(&run.argv);
            w.strs(&run.env);
            w.str(&run.cwd);
            w.str(&run.hostname);
            w.str(&run.state_root);
            w.bool(run.isolate_network);
        }
        HostFrame::Shutdown => w.u8(HOST_SHUTDOWN),
    }
    w.0
}

fn encode_guest(frame: &GuestFrame) -> Vec<u8> {
    let mut w = Buf::new();
    match frame {
        GuestFrame::Output { stream, data } => {
            w.u8(GUEST_OUTPUT);
            w.u8(*stream);
            w.bytes(data);
        }
        GuestFrame::Status { code } => {
            w.u8(GUEST_STATUS);
            w.i32(*code);
        }
        GuestFrame::Error {
            code,
            message,
            detail,
        } => {
            w.u8(GUEST_ERROR);
            w.i32(*code);
            w.str(message);
            w.str(detail);
        }
    }
    w.0
}

fn decode_host(body: &[u8]) -> io::Result<HostFrame> {
    let mut r = Cursor::new(body);
    let frame = match r.u8()? {
        HOST_RUN => HostFrame::Run(Run {
            rootfs: r.str()?,
            argv: r.strs()?,
            env: r.strs()?,
            cwd: r.str()?,
            hostname: r.str()?,
            state_root: r.str()?,
            isolate_network: r.bool()?,
        }),
        HOST_SHUTDOWN => HostFrame::Shutdown,
        other => return Err(invalid(format!("unknown host tag {other}"))),
    };
    r.finish()?;
    Ok(frame)
}

fn decode_guest(body: &[u8]) -> io::Result<GuestFrame> {
    let mut r = Cursor::new(body);
    let frame = match r.u8()? {
        GUEST_OUTPUT => GuestFrame::Output {
            stream: r.u8()?,
            data: r.bytes()?.to_vec(),
        },
        GUEST_STATUS => GuestFrame::Status { code: r.i32()? },
        GUEST_ERROR => GuestFrame::Error {
            code: r.i32()?,
            message: r.str()?,
            detail: r.str()?,
        },
        other => return Err(invalid(format!("unknown guest tag {other}"))),
    };
    r.finish()?;
    Ok(frame)
}

struct Buf(Vec<u8>);

impl Buf {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.0.extend(value.to_le_bytes());
    }

    fn i32(&mut self, value: i32) {
        self.0.extend(value.to_le_bytes());
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn str(&mut self, value: &str) {
        let len = u32::try_from(value.len()).expect("string fits in u32");
        self.u32(len);
        self.0.extend(value.as_bytes());
    }

    fn strs(&mut self, values: &[String]) {
        let len = u32::try_from(values.len()).expect("list fits in u32");
        self.u32(len);
        for value in values {
            self.str(value);
        }
    }

    fn bytes(&mut self, value: &[u8]) {
        let len = u32::try_from(value.len()).expect("bytes fit in u32");
        self.u32(len);
        self.0.extend(value);
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn u8(&mut self) -> io::Result<u8> {
        let byte = *self
            .buf
            .get(self.at)
            .ok_or_else(|| invalid("truncated frame"))?;
        self.at += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| invalid("truncated frame"))?;
        let slice = self
            .buf
            .get(self.at..end)
            .ok_or_else(|| invalid("truncated frame"))?;
        self.at = end;
        Ok(slice)
    }

    /// `min_each` is the smallest encoded size of one element. A count larger
    /// than the remaining frame cannot be allocated.
    fn bounded_count(&mut self, min_each: usize) -> io::Result<usize> {
        let len = self.u32()? as usize;
        let remaining = self.buf.len().saturating_sub(self.at);
        if min_each == 0 || len > remaining / min_each {
            return Err(invalid("list is longer than the frame"));
        }
        Ok(len)
    }

    fn u32(&mut self) -> io::Result<u32> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn i32(&mut self) -> io::Result<i32> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(i32::from_le_bytes(raw))
    }

    fn bool(&mut self) -> io::Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(invalid(format!("invalid bool {other}"))),
        }
    }

    fn str(&mut self) -> io::Result<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| invalid("string is not utf-8"))
    }

    fn strs(&mut self) -> io::Result<Vec<String>> {
        let len = self.bounded_count(4)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.str()?);
        }
        Ok(out)
    }

    fn bytes(&mut self) -> io::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn finish(self) -> io::Result<()> {
        if self.at == self.buf.len() {
            Ok(())
        } else {
            Err(invalid("trailing bytes in frame"))
        }
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip_host(frame: HostFrame) {
        let mut buf = Vec::new();
        write_host_frame(&mut buf, &frame).unwrap();
        let decoded = read_host_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, frame);
    }

    fn roundtrip_guest(frame: GuestFrame) {
        let mut buf = Vec::new();
        write_guest_frame(&mut buf, &frame).unwrap();
        let decoded = read_guest_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn host_frames_roundtrip() {
        roundtrip_host(HostFrame::Run(Run {
            rootfs: "/mnt/rootfs".into(),
            argv: vec!["/bin/echo".into(), "hi".into()],
            env: vec!["PATH=/bin".into()],
            cwd: "/".into(),
            hostname: "runner".into(),
            state_root: String::new(),
            isolate_network: true,
        }));
        roundtrip_host(HostFrame::Shutdown);
    }

    #[test]
    fn guest_frames_roundtrip() {
        roundtrip_guest(GuestFrame::Output {
            stream: STDOUT,
            data: b"hi\0\xff".to_vec(),
        });
        roundtrip_guest(GuestFrame::Status { code: 0 });
        roundtrip_guest(GuestFrame::Error {
            code: 5,
            message: "run failed".into(),
            detail: "exec".into(),
        });
    }

    #[test]
    fn rejects_a_truncated_frame_and_bad_utf8() {
        let err = read_host_frame(&mut Cursor::new(&[2, 0, 0, 0, 1])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        let mut body = vec![HOST_SHUTDOWN, 0];
        let mut framed = (body.len() as u32).to_le_bytes().to_vec();
        framed.append(&mut body);
        let err = read_host_frame(&mut Cursor::new(framed)).unwrap_err();
        assert!(err.to_string().contains("trailing"));

        let mut bad = Vec::new();
        bad.extend(6u32.to_le_bytes());
        bad.push(HOST_RUN);
        bad.extend(1u32.to_le_bytes());
        bad.push(0xff);
        let err = read_host_frame(&mut Cursor::new(bad)).unwrap_err();
        assert!(err.to_string().contains("utf-8"));
    }

    #[test]
    fn rejects_an_oversized_length() {
        let mut buf = (MAX_FRAME_LEN + 1).to_le_bytes().to_vec();
        buf.extend([0u8; 8]);
        let err = read_guest_frame(&mut Cursor::new(buf)).unwrap_err();
        assert!(err.to_string().contains("limit"));
    }

    #[test]
    fn rejects_a_list_count_larger_than_the_frame() {
        let count = 0x0100_0000u32.to_le_bytes();
        let mut cursor = crate::Cursor::new(&count);
        let err = cursor.strs().unwrap_err();
        assert!(err.to_string().contains("longer than the frame"));
    }
}
