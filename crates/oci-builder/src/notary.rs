// SPDX-License-Identifier: Apache-2.0

//! Sign pushed images with Notary v1.1.0 signatures.
//!
//! After an image is pushed, optionally sign the manifest as a referrer artifact.

use std::path::Path;

use crate::error::{Error, ErrorCode};

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

// TODO: sign(material: &SigningMaterial, manifest: &Payload) -> Result<Vec<u8>>
// Fetch the pushed manifest from the registry after successful push, sign it
// with the provided key and cert chain using oci_util::signature::{sign_jws,sign_cose},
// and upload the signature as a referrer artifact using Buildah's remote API.
