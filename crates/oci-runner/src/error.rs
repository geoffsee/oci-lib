// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use std::fmt;

/// Failure returned by the runtime engine or argument validation.
///
/// `code` is stable and is the process exit code used by `oci-runner`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    message: String,
    detail: String,
}

/// Stable failure class. Values match the C ABI and CLI exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    /// A caller-supplied path, flag, or string is unusable.
    InvalidArgument = 1,
    /// The rootfs or required file is not found.
    NotFound = 3,
    /// The kernel, user namespace, or filesystem setup cannot run the container.
    Prerequisite = 4,
    /// The container execution failed.
    Run = 5,
    /// The operation is unsupported on this platform or operating system.
    Unsupported = 8,
    /// An unexpected internal error occurred.
    Internal = 9,
    /// The runtime is in the wrong state for this operation.
    State = 10,
}

impl ErrorCode {
    /// Convert the error code to a process exit code.
    pub fn as_exit(self) -> i32 {
        self as i32
    }

    pub(crate) fn from_raw(code: i32) -> Self {
        match code {
            1 => Self::InvalidArgument,
            3 => Self::NotFound,
            4 => Self::Prerequisite,
            5 => Self::Run,
            8 => Self::Unsupported,
            10 => Self::State,
            _ => Self::Internal,
        }
    }

    fn fallback(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid argument",
            Self::NotFound => "not found",
            Self::Prerequisite => "missing prerequisite",
            Self::Run => "run failed",
            Self::Unsupported => "unsupported on this platform",
            Self::Internal => "internal error",
            Self::State => "runtime is in the wrong state",
        }
    }
}

impl Error {
    /// Construct a new error with an error code, message, and detail.
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

    /// The category and exit status for this failure.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// A short description of what failed.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Optional detailed diagnostics or stderr from the underlying engine.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub(crate) fn from_ffi(err: &crate::ffi::RorError) -> Self {
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

pub(crate) unsafe fn read_buf(buf: &crate::ffi::RorBuffer) -> String {
    if buf.data.is_null() || buf.len == 0 {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf.data as *const u8, buf.len) };
    String::from_utf8_lossy(bytes).into_owned()
}
