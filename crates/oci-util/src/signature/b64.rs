//! Base64 helpers for JWS and X.509 certificate chains.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use super::error::{ErrorKind, SignatureError};

pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn b64url_decode(text: &str) -> Result<Vec<u8>, SignatureError> {
    URL_SAFE_NO_PAD.decode(text).map_err(|_| {
        SignatureError::new(
            ErrorKind::Encoding,
            "invalid base64url value in JWS envelope",
        )
    })
}

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(text: &str) -> Result<Vec<u8>, SignatureError> {
    STANDARD.decode(text).map_err(|_| {
        SignatureError::new(
            ErrorKind::Encoding,
            "invalid base64 certificate or timestamp value",
        )
    })
}
