// SPDX-License-Identifier: Apache-2.0

//! Errors from shared Virtualization host helpers.
//!
//! Product crates map [`VmErrorKind`] onto their own `ErrorCode`.

use std::fmt;

/// Classification of a host/guest failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmErrorKind {
    /// Caller passed a bad path or argument.
    InvalidArgument,
    /// Host is missing a required capability or image.
    Prerequisite,
    /// Session state is wrong (already open, not open, …).
    State,
    /// Unexpected failure inside the host glue.
    Internal,
}

/// A Virtualization host error with an optional detail string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmError {
    /// Error classification.
    pub kind: VmErrorKind,
    /// Short message.
    pub message: String,
    /// Longer remediation or context; may be empty.
    pub detail: String,
}

impl VmError {
    /// Construct an error with an empty detail.
    pub fn new(kind: VmErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: String::new(),
        }
    }

    /// Construct an error with a detail string.
    pub fn with_detail(
        kind: VmErrorKind,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.message, self.detail)
        }
    }
}

impl std::error::Error for VmError {}
