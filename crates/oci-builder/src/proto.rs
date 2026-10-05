// SPDX-License-Identifier: Apache-2.0

//! Frames carried over the virtio socket between a macOS host and the Linux guest.
//!
//! A frame is a little-endian `u32` byte length followed by a body. The first
//! body byte is the message tag. Strings are a `u32` length plus UTF-8 bytes.
//! The C ABI is not used here: it holds borrowed pointers and a log callback.

use std::io::{self, Read, Write};

/// Guest virtio-vsock port the agent listens on. The host connects to it.
pub const VSOCK_PORT: u32 = 5252;

/// Largest accepted body. Larger lengths are rejected before allocation.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

const HOST_INIT: u8 = 1;
const HOST_BUILD: u8 = 2;
const HOST_TAG: u8 = 3;
const HOST_PUSH: u8 = 4;
const HOST_DIAGNOSE: u8 = 5;
const HOST_CANCEL: u8 = 6;
const HOST_SHUTDOWN: u8 = 7;

const GUEST_LOG: u8 = 1;
const GUEST_RESULT: u8 = 2;
const GUEST_ERROR: u8 = 3;

/// Host to guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFrame {
    Init(Init),
    Build(Build),
    Tag { image: String, new_name: String },
    Push(Push),
    Diagnose,
    Cancel { token: u64 },
    Shutdown,
}

/// Storage and registry settings for [`HostFrame::Init`].
///
/// Empty paths mean "guest default". `storage_driver` is `vfs`, `overlay`, or
/// empty. `log_level` is the Buildah level name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Init {
    pub storage_root: String,
    pub run_root: String,
    pub storage_driver: String,
    pub storage_opts: Vec<String>,
    pub registries_conf: String,
    pub signature_policy: String,
    pub auth_file: String,
    pub insecure: bool,
    pub log_level: String,
}

/// One image build. Paths are guest paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    pub dockerfile: String,
    pub context_dir: String,
    pub tag: String,
    pub target: String,
    pub isolation: String,
    pub format: String,
    pub pull: String,
    pub os: String,
    pub arch: String,
    pub variant: String,
    pub build_args: Vec<(String, String)>,
    pub labels: Vec<(String, String)>,
    /// `1` commits a layer per instruction, `0` does not.
    pub layers: i32,
    pub no_cache: bool,
    pub squash: bool,
    pub quiet: bool,
    /// `0` means the build cannot be cancelled.
    pub cancel_token: u64,
}

/// One registry push. An empty `format` keeps the source manifest type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    pub image: String,
    pub destination: String,
    pub username: String,
    pub password: String,
    pub format: String,
    pub insecure: bool,
    pub cancel_token: u64,
}

/// Guest to host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestFrame {
    Log {
        stream: u8,
        message: String,
    },
    Result {
        image_id: String,
        digest: String,
        reference: String,
    },
    Error {
        code: i32,
        message: String,
        detail: String,
    },
}

/// Log stream codes. They match the C ABI `ROB_LOG_*` values.
pub const LOG_PROGRESS: u8 = 0;
pub const LOG_INFO: u8 = 1;
pub const LOG_WARN: u8 = 2;
pub const LOG_ERROR: u8 = 3;

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
        HostFrame::Init(init) => {
            w.u8(HOST_INIT);
            w.str(&init.storage_root);
            w.str(&init.run_root);
            w.str(&init.storage_driver);
            w.strs(&init.storage_opts);
            w.str(&init.registries_conf);
            w.str(&init.signature_policy);
            w.str(&init.auth_file);
            w.bool(init.insecure);
            w.str(&init.log_level);
        }
        HostFrame::Build(build) => {
            w.u8(HOST_BUILD);
            w.str(&build.dockerfile);
            w.str(&build.context_dir);
            w.str(&build.tag);
            w.str(&build.target);
            w.str(&build.isolation);
            w.str(&build.format);
            w.str(&build.pull);
            w.str(&build.os);
            w.str(&build.arch);
            w.str(&build.variant);
            w.pairs(&build.build_args);
            w.pairs(&build.labels);
            w.i32(build.layers);
            w.bool(build.no_cache);
            w.bool(build.squash);
            w.bool(build.quiet);
            w.u64(build.cancel_token);
        }
        HostFrame::Tag { image, new_name } => {
            w.u8(HOST_TAG);
            w.str(image);
            w.str(new_name);
        }
        HostFrame::Push(push) => {
            w.u8(HOST_PUSH);
            w.str(&push.image);
            w.str(&push.destination);
            w.str(&push.username);
            w.str(&push.password);
            w.str(&push.format);
            w.bool(push.insecure);
            w.u64(push.cancel_token);
        }
        HostFrame::Diagnose => w.u8(HOST_DIAGNOSE),
        HostFrame::Cancel { token } => {
            w.u8(HOST_CANCEL);
            w.u64(*token);
        }
        HostFrame::Shutdown => w.u8(HOST_SHUTDOWN),
    }
    w.0
}

fn encode_guest(frame: &GuestFrame) -> Vec<u8> {
    let mut w = Buf::new();
    match frame {
        GuestFrame::Log { stream, message } => {
            w.u8(GUEST_LOG);
            w.u8(*stream);
            w.str(message);
        }
        GuestFrame::Result {
            image_id,
            digest,
            reference,
        } => {
            w.u8(GUEST_RESULT);
            w.str(image_id);
            w.str(digest);
            w.str(reference);
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
        HOST_INIT => HostFrame::Init(Init {
            storage_root: r.str()?,
            run_root: r.str()?,
            storage_driver: r.str()?,
            storage_opts: r.strs()?,
            registries_conf: r.str()?,
            signature_policy: r.str()?,
            auth_file: r.str()?,
            insecure: r.bool()?,
            log_level: r.str()?,
        }),
        HOST_BUILD => HostFrame::Build(Build {
            dockerfile: r.str()?,
            context_dir: r.str()?,
            tag: r.str()?,
            target: r.str()?,
            isolation: r.str()?,
            format: r.str()?,
            pull: r.str()?,
            os: r.str()?,
            arch: r.str()?,
            variant: r.str()?,
            build_args: r.pairs()?,
            labels: r.pairs()?,
            layers: r.i32()?,
            no_cache: r.bool()?,
            squash: r.bool()?,
            quiet: r.bool()?,
            cancel_token: r.u64()?,
        }),
        HOST_TAG => HostFrame::Tag {
            image: r.str()?,
            new_name: r.str()?,
        },
        HOST_PUSH => HostFrame::Push(Push {
            image: r.str()?,
            destination: r.str()?,
            username: r.str()?,
            password: r.str()?,
            format: r.str()?,
            insecure: r.bool()?,
            cancel_token: r.u64()?,
        }),
        HOST_DIAGNOSE => HostFrame::Diagnose,
        HOST_CANCEL => HostFrame::Cancel { token: r.u64()? },
        HOST_SHUTDOWN => HostFrame::Shutdown,
        other => return Err(invalid(format!("unknown host tag {other}"))),
    };
    r.finish()?;
    Ok(frame)
}

fn decode_guest(body: &[u8]) -> io::Result<GuestFrame> {
    let mut r = Cursor::new(body);
    let frame = match r.u8()? {
        GUEST_LOG => GuestFrame::Log {
            stream: r.u8()?,
            message: r.str()?,
        },
        GUEST_RESULT => GuestFrame::Result {
            image_id: r.str()?,
            digest: r.str()?,
            reference: r.str()?,
        },
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

    fn u64(&mut self, value: u64) {
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

    fn pairs(&mut self, values: &[(String, String)]) {
        let len = u32::try_from(values.len()).expect("list fits in u32");
        self.u32(len);
        for (key, value) in values {
            self.str(key);
            self.str(value);
        }
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

    fn bytes(&mut self, len: usize) -> io::Result<&'a [u8]> {
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
        raw.copy_from_slice(self.bytes(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn u64(&mut self) -> io::Result<u64> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.bytes(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn i32(&mut self) -> io::Result<i32> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.bytes(4)?);
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
        let bytes = self.bytes(len)?;
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

    fn pairs(&mut self) -> io::Result<Vec<(String, String)>> {
        let len = self.bounded_count(8)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push((self.str()?, self.str()?));
        }
        Ok(out)
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
        roundtrip_host(HostFrame::Init(Init {
            storage_root: "/mnt/root".into(),
            run_root: "/mnt/runroot".into(),
            storage_driver: "vfs".into(),
            storage_opts: vec!["a=b".into()],
            registries_conf: String::new(),
            signature_policy: "/mnt/policy/policy.json".into(),
            auth_file: String::new(),
            insecure: true,
            log_level: "warn".into(),
        }));
        roundtrip_host(HostFrame::Build(Build {
            dockerfile: "/mnt/context/Dockerfile".into(),
            context_dir: "/mnt/context".into(),
            tag: "localhost/scratch-copy:latest".into(),
            target: String::new(),
            isolation: "chroot".into(),
            format: "oci".into(),
            pull: "never".into(),
            os: String::new(),
            arch: String::new(),
            variant: String::new(),
            build_args: vec![("GREETING".into(), "world".into())],
            labels: vec![("a".into(), "b".into())],
            layers: 1,
            no_cache: false,
            squash: true,
            quiet: false,
            cancel_token: 7,
        }));
        roundtrip_host(HostFrame::Tag {
            image: "a".into(),
            new_name: "b".into(),
        });
        roundtrip_host(HostFrame::Push(Push {
            image: "a".into(),
            destination: "localhost:5000/a".into(),
            username: "user".into(),
            password: "secret".into(),
            format: String::new(),
            insecure: true,
            cancel_token: 0,
        }));
        roundtrip_host(HostFrame::Diagnose);
        roundtrip_host(HostFrame::Cancel { token: 9 });
        roundtrip_host(HostFrame::Shutdown);
    }

    #[test]
    fn guest_frames_roundtrip() {
        roundtrip_guest(GuestFrame::Log {
            stream: LOG_WARN,
            message: "pulling\n".into(),
        });
        roundtrip_guest(GuestFrame::Result {
            image_id: "sha256:abc".into(),
            digest: "sha256:def".into(),
            reference: "localhost/app:latest".into(),
        });
        roundtrip_guest(GuestFrame::Error {
            code: 5,
            message: "build failed".into(),
            detail: "COPY missing".into(),
        });
    }

    #[test]
    fn rejects_a_truncated_frame_and_bad_utf8() {
        let err = read_host_frame(&mut Cursor::new(&[2, 0, 0, 0, 1])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        let mut short = Vec::new();
        short.extend(1u32.to_le_bytes());
        short.push(HOST_INIT);
        let err = read_host_frame(&mut Cursor::new(short)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("truncated"));

        let mut body = vec![HOST_SHUTDOWN, 0];
        let mut framed = (body.len() as u32).to_le_bytes().to_vec();
        framed.append(&mut body);
        let err = read_host_frame(&mut Cursor::new(framed)).unwrap_err();
        assert!(err.to_string().contains("trailing"));

        let mut bad = Vec::new();
        bad.extend(6u32.to_le_bytes());
        bad.push(HOST_TAG);
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
        let mut cursor = super::Cursor::new(&count);
        let err = cursor.strs().unwrap_err();
        assert!(err.to_string().contains("longer than the frame"));
        let mut cursor = super::Cursor::new(&count);
        let err = cursor.pairs().unwrap_err();
        assert!(err.to_string().contains("longer than the frame"));
    }
}
