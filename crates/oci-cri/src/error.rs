// SPDX-License-Identifier: Apache-2.0

//! Stable failure classes shared by the library, the CLI exit status and the
//! guest protocol.

use std::fmt;

/// Stable failure class. Values match the C ABI and CLI exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    /// A caller-supplied path, flag, or string is unusable.
    InvalidArgument = 1,
    /// The sandbox, container, image, or file is not found.
    NotFound = 3,
    /// The kernel, user namespace, VM, or filesystem setup cannot run containers.
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

    #[allow(dead_code)]
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

/// Failure returned by the runtime engine, the VM host, or validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    message: String,
    detail: String,
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

    /// Optional detailed diagnostics.
    pub fn detail(&self) -> &str {
        &self.detail
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

/// Map a crate error onto a gRPC status for the CRI handlers.
impl From<Error> for tonic::Status {
    fn from(err: Error) -> Self {
        let message = err.to_string();
        match err.code() {
            ErrorCode::InvalidArgument => tonic::Status::invalid_argument(message),
            ErrorCode::NotFound => tonic::Status::not_found(message),
            ErrorCode::State => tonic::Status::failed_precondition(message),
            ErrorCode::Unsupported => tonic::Status::unimplemented(message),
            _ => tonic::Status::internal(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_message_uses_fallback() {
        let err = Error::new(ErrorCode::NotFound, "", "path");
        assert_eq!(err.message(), "not found");
        assert_eq!(err.detail(), "path");
        assert_eq!(err.to_string(), "not found\npath");
    }

    #[test]
    fn display_omits_blank_detail() {
        let err = Error::new(ErrorCode::Run, "boom", "");
        assert_eq!(err.to_string(), "boom");
    }

    #[test]
    fn from_raw_maps_known_codes_and_defaults_to_internal() {
        assert_eq!(ErrorCode::from_raw(1), ErrorCode::InvalidArgument);
        assert_eq!(ErrorCode::from_raw(3), ErrorCode::NotFound);
        assert_eq!(ErrorCode::from_raw(4), ErrorCode::Prerequisite);
        assert_eq!(ErrorCode::from_raw(5), ErrorCode::Run);
        assert_eq!(ErrorCode::from_raw(8), ErrorCode::Unsupported);
        assert_eq!(ErrorCode::from_raw(10), ErrorCode::State);
        assert_eq!(ErrorCode::from_raw(99), ErrorCode::Internal);
        assert_eq!(ErrorCode::from_raw(9), ErrorCode::Internal);
    }

    #[test]
    fn maps_to_grpc_status_codes() {
        assert_eq!(
            tonic::Status::from(Error::new(ErrorCode::InvalidArgument, "bad", "")).code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            tonic::Status::from(Error::new(ErrorCode::NotFound, "gone", "")).code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            tonic::Status::from(Error::new(ErrorCode::State, "wrong", "")).code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            tonic::Status::from(Error::new(ErrorCode::Unsupported, "nope", "")).code(),
            tonic::Code::Unimplemented
        );
        assert_eq!(
            tonic::Status::from(Error::new(ErrorCode::Internal, "oops", "")).code(),
            tonic::Code::Internal
        );
        assert_eq!(
            tonic::Status::from(Error::new(ErrorCode::Run, "fail", "")).code(),
            tonic::Code::Internal
        );
    }

    #[test]
    fn as_exit_matches_repr() {
        assert_eq!(ErrorCode::InvalidArgument.as_exit(), 1);
        assert_eq!(ErrorCode::Unsupported.as_exit(), 8);
    }
}
