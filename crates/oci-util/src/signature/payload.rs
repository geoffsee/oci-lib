//! Notary signature payload (`application/vnd.cncf.notary.payload.v1+json`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::error::{ErrorKind, SignatureError};

/// Media type of the Notary Project signature payload.
pub const PAYLOAD_MEDIA_TYPE: &str = "application/vnd.cncf.notary.payload.v1+json";

/// Annotation keys with this prefix are reserved on the signed payload.
pub const NOTARY_ANNOTATION_PREFIX: &str = "io.cncf.notary";

/// OCI descriptor carried by a Notary payload or signature manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    /// Media type of the referenced content.
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// Digest of the referenced content, `algorithm:hex`.
    pub digest: String,
    /// Size of the referenced content, in bytes.
    pub size: i64,
    /// Optional artifact type. For an image manifest this is `config.mediaType`.
    #[serde(rename = "artifactType", skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    /// Optional string annotations. Keys starting with `io.cncf.notary` are rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

impl Descriptor {
    /// Check the descriptor fields required by the Notary payload.
    pub fn validate(&self) -> Result<(), SignatureError> {
        if self.media_type.is_empty() {
            return Err(SignatureError::new(
                ErrorKind::Payload,
                "descriptor mediaType is empty",
            ));
        }
        validate_digest(&self.digest)?;
        if self.size < 0 {
            return Err(SignatureError::new(
                ErrorKind::Payload,
                "descriptor size is negative",
            ));
        }
        if let Some(artifact_type) = &self.artifact_type {
            if artifact_type.is_empty() {
                return Err(SignatureError::new(
                    ErrorKind::Payload,
                    "descriptor artifactType is empty",
                ));
            }
        }
        if let Some(annotations) = &self.annotations {
            for key in annotations.keys() {
                if key.starts_with(NOTARY_ANNOTATION_PREFIX) {
                    return Err(SignatureError::new(
                        ErrorKind::Payload,
                        format!(
                            "annotation key `{key}` uses reserved prefix {NOTARY_ANNOTATION_PREFIX}"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Signed Notary payload. The only top-level property is `targetArtifact`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    /// Descriptor of the artifact manifest that was signed.
    #[serde(rename = "targetArtifact")]
    pub target_artifact: Descriptor,
}

impl Payload {
    /// Encode the payload as canonical JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SignatureError> {
        self.target_artifact.validate()?;
        serde_json::to_vec(self).map_err(|err| {
            SignatureError::new(
                ErrorKind::Payload,
                format!("failed to encode payload: {err}"),
            )
        })
    }

    /// Parse a Notary payload and reject reserved annotation keys.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let payload: Self = serde_json::from_slice(bytes).map_err(|err| {
            SignatureError::new(ErrorKind::Payload, format!("invalid Notary payload: {err}"))
        })?;
        payload.target_artifact.validate()?;
        Ok(payload)
    }
}

pub(crate) fn validate_digest(digest: &str) -> Result<(), SignatureError> {
    let Some((algorithm, hex)) = digest.split_once(':') else {
        return Err(SignatureError::new(
            ErrorKind::Payload,
            "descriptor digest is missing an algorithm prefix",
        ));
    };
    if algorithm.is_empty() || hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SignatureError::new(
            ErrorKind::Payload,
            "descriptor digest is not algorithm:hex",
        ));
    }
    let expected = match algorithm {
        "sha256" => Some(64),
        "sha384" => Some(96),
        "sha512" => Some(128),
        _ => None,
    };
    if let Some(length) = expected {
        if hex.len() != length {
            return Err(SignatureError::new(
                ErrorKind::Payload,
                format!("descriptor digest length does not match {algorithm}"),
            ));
        }
    }
    Ok(())
}
