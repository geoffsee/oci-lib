//! Errors from Notary signature parsing and verification.

use std::fmt;

/// Category of a signature failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Payload JSON or descriptor rules were violated.
    Payload,
    /// Signature manifest or descriptor rules were violated.
    Manifest,
    /// A certificate or chain rule was violated.
    Certificate,
    /// The signature algorithm is unsupported or does not match the leaf key.
    Algorithm,
    /// The primitive signature did not verify.
    Signature,
    /// The trust policy is invalid or does not apply.
    Policy,
    /// A timestamp countersignature could not be accepted.
    Timestamp,
    /// An OCI referrers index could not be used.
    Referrers,
    /// Bytes were not valid JSON, CBOR, or base64.
    Encoding,
}

/// Failure while signing, parsing, or verifying a Notary signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureError {
    kind: ErrorKind,
    message: String,
}

impl SignatureError {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Category of this failure.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SignatureError {}
