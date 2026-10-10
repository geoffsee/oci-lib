// SPDX-License-Identifier: Apache-2.0

//! Sign pushed images with Notary v1.1.0 signatures.
//!
//! After an image is pushed, optionally sign the manifest as a referrer artifact.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, ErrorCode};
use oci_util::signature::{self, Descriptor, Payload, SignatureManifest, SignedAttributes};

/// Validate signing configuration and load key/certificate material.
pub(crate) fn validate_signing_config(
    key_path: Option<&Path>,
    cert_paths: &[impl AsRef<Path>],
) -> Result<Option<SigningMaterial>, Error> {
    let key_path = match key_path {
        None => return Ok(None),
        Some(p) => p,
    };

    if cert_paths.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "signing key is configured but certificate chain is empty",
            "provide at least one certificate file with signing_cert_chain",
        ));
    }

    let key_bytes = std::fs::read(key_path).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("cannot read signing key: {err}"),
            key_path.display().to_string(),
        )
    })?;

    let mut cert_bytes = Vec::new();
    for (i, cert_path) in cert_paths.iter().enumerate() {
        let path = cert_path.as_ref();
        match std::fs::read(path) {
            Ok(bytes) => cert_bytes.push(bytes),
            Err(err) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("cannot read certificate {i}: {err}"),
                    path.display().to_string(),
                ));
            }
        }
    }

    Ok(Some(SigningMaterial {
        key: key_bytes,
        certificates: cert_bytes,
    }))
}

/// Loaded key and certificate material ready for signing.
#[allow(dead_code)]
pub(crate) struct SigningMaterial {
    pub key: Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
}

/// Sign an image manifest using the Notary X.509 JWS profile.
pub(crate) fn sign_manifest(
    material: &SigningMaterial,
    target: Descriptor,
) -> Result<(SignatureManifest, Vec<u8>), Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                "clock is before the Unix epoch",
                err.to_string(),
            )
        })?
        .as_secs() as i64;
    let payload = Payload {
        target_artifact: target,
    };
    let envelope = signature::sign_jws(
        &payload,
        &material.key,
        &material.certificates,
        &SignedAttributes::x509(now),
        Some("oci-builder"),
    )
    .map_err(|err| {
        Error::new(
            ErrorCode::Push,
            "cannot sign pushed manifest",
            err.to_string(),
        )
    })?;
    let manifest = signature::signature_manifest(
        &payload.target_artifact,
        signature::JWS_MEDIA_TYPE,
        &envelope,
        &material.certificates,
    )
    .map_err(|err| {
        Error::new(
            ErrorCode::Push,
            "cannot build signature manifest",
            err.to_string(),
        )
    })?;
    Ok((manifest, envelope))
}
