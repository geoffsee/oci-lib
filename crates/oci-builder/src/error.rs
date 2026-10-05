// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::fmt;

/// Failure returned by the engine or by argument checking.
///
/// `code` is stable and is the process exit code used by `oci-builder`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    message: String,
    detail: String,
}

/// Stable failure class. Values match the C ABI and the CLI exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    /// A caller-supplied path, flag, or string is unusable.
    InvalidArgument = 1,
    /// The operation's cancel token fired, or the token was already gone.
    Cancelled = 2,
    /// The named image is not in local storage.
    NotFound = 3,
    /// The kernel, user namespace, or storage setup cannot run Buildah.
    Prerequisite = 4,
    /// The Dockerfile build failed.
    Build = 5,
    /// The registry push failed.
    Push = 6,
    /// Tagging the local image failed.
    Tag = 7,
    /// This process is not a Linux build of the engine.
    Unsupported = 8,
    /// The shim failed in a way that is not one of the cases above.
    Internal = 9,
    /// The process store is already open, or it was used before `open`.
    State = 10,
}

impl ErrorCode {
    pub fn as_exit(self) -> i32 {
        self as i32
    }

    pub(crate) fn from_raw(code: i32) -> Self {
        match code {
            1 => Self::InvalidArgument,
            2 => Self::Cancelled,
            3 => Self::NotFound,
            4 => Self::Prerequisite,
            5 => Self::Build,
            6 => Self::Push,
            7 => Self::Tag,
            8 => Self::Unsupported,
            10 => Self::State,
            _ => Self::Internal,
        }
    }

    fn fallback(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid argument",
            Self::Cancelled => "operation cancelled",
            Self::NotFound => "image not found",
            Self::Prerequisite => "missing prerequisite",
            Self::Build => "build failed",
            Self::Push => "push failed",
            Self::Tag => "tag failed",
            Self::Unsupported => "unsupported on this platform",
            Self::Internal => "internal error",
            Self::State => "store is in the wrong state",
        }
    }
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>, detail: impl Into<String>) -> Self {
        let message = message.into();
        let message = if message.is_empty() {
            code.fallback().to_string()
        } else {
            message
        };
        Self {
            code,
            message,
            detail: detail.into(),
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub(crate) fn from_ffi(err: &crate::ffi::RobError) -> Self {
        let code = ErrorCode::from_raw(err.code);
        let message = unsafe { read_buf(&err.message) };
        let detail = unsafe { read_buf(&err.detail) };
        Self::new(code, message, detail)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}\n{}", self.message, self.detail)
        }
    }
}

impl std::error::Error for Error {}

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) unsafe fn read_buf(buf: &crate::ffi::RobBuffer) -> String {
    if buf.data.is_null() || buf.len == 0 {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.data as *const u8, buf.len) };
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_the_abi() {
        assert_eq!(ErrorCode::InvalidArgument.as_exit(), 1);
        assert_eq!(ErrorCode::Cancelled.as_exit(), 2);
        assert_eq!(ErrorCode::Prerequisite.as_exit(), 4);
        assert_eq!(ErrorCode::Unsupported.as_exit(), 8);
        assert_eq!(ErrorCode::State.as_exit(), 10);
        assert_eq!(ErrorCode::from_raw(0), ErrorCode::Internal);
        assert_eq!(ErrorCode::from_raw(6), ErrorCode::Push);
    }

    #[test]
    fn display_includes_detail() {
        let err = Error::new(ErrorCode::Prerequisite, "blocked", "status: blocked\n");
        assert_eq!(err.to_string(), "blocked\nstatus: blocked\n");
        assert_eq!(err.message(), "blocked");
        assert_eq!(err.detail(), "status: blocked\n");
    }
}
