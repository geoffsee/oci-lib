//! Notary signature manifest stored as an OCI image manifest.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::{ErrorKind, SignatureError};
use super::payload::Descriptor;

/// OCI image manifest media type used for a Notary signature.
pub const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// OCI image index media type used by the referrers API.
pub const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// Config media type that marks a manifest as a Notary signature.
pub const SIGNATURE_CONFIG_MEDIA_TYPE: &str = "application/vnd.cncf.notary.signature";

/// Artifact type of a Notary signature referrer.
pub const SIGNATURE_ARTIFACT_TYPE: &str = "application/vnd.cncf.notary.signature";

/// JWS envelope media type.
pub const JWS_MEDIA_TYPE: &str = "application/jose+json";

/// COSE envelope media type.
pub const COSE_MEDIA_TYPE: &str = "application/cose";

/// Required manifest annotation. The value is a JSON array of SHA-256 certificate fingerprints.
pub const THUMBPRINT_ANNOTATION: &str = "io.cncf.notary.x509chain.thumbprint#S256";

/// Config blob used when the signature has no configuration. Two bytes: `{}`.
pub const SIGNATURE_CONFIG_BYTES: &[u8] = b"{}";

/// Digest of [`SIGNATURE_CONFIG_BYTES`].
pub const SIGNATURE_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// Size of [`SIGNATURE_CONFIG_BYTES`].
pub const SIGNATURE_CONFIG_SIZE: i64 = 2;

/// OCI manifest that references one Notary signature envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureManifest {
    /// Must be `2`.
    #[serde(rename = "schemaVersion")]
    pub schema_version: i32,
    /// Must be [`OCI_MANIFEST_MEDIA_TYPE`].
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// Set to [`SIGNATURE_ARTIFACT_TYPE`] when this crate builds a manifest.
    #[serde(rename = "artifactType", skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    /// Descriptor of the signature config blob.
    pub config: Descriptor,
    /// Exactly one layer, the signature envelope.
    pub layers: Vec<Descriptor>,
    /// Descriptor of the signed artifact manifest.
    pub subject: Descriptor,
    /// Manifest annotations. The thumbprint annotation is required.
    pub annotations: BTreeMap<String, String>,
}

impl SignatureManifest {
    /// Encode the manifest as JSON.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SignatureError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|err| {
            SignatureError::new(
                ErrorKind::Manifest,
                format!("failed to encode signature manifest: {err}"),
            )
        })
    }

    /// Parse a signature manifest.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let manifest: Self = serde_json::from_slice(bytes).map_err(|err| {
            SignatureError::new(
                ErrorKind::Manifest,
                format!("invalid signature manifest: {err}"),
            )
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Check the manifest restrictions from the Notary signature specification.
    pub fn validate(&self) -> Result<(), SignatureError> {
        if self.schema_version != 2 {
            return Err(SignatureError::new(
                ErrorKind::Manifest,
                "signature manifest schemaVersion must be 2",
            ));
        }
        if self.media_type != OCI_MANIFEST_MEDIA_TYPE {
            return Err(SignatureError::new(
                ErrorKind::Manifest,
                "signature manifest mediaType must be application/vnd.oci.image.manifest.v1+json",
            ));
        }
        if let Some(artifact_type) = &self.artifact_type {
            if artifact_type != SIGNATURE_ARTIFACT_TYPE {
                return Err(SignatureError::new(
                    ErrorKind::Manifest,
                    "signature manifest artifactType is not a Notary signature",
                ));
            }
        }
        self.config.validate().map_err(manifest_error)?;
        if self.config.media_type != SIGNATURE_CONFIG_MEDIA_TYPE {
            return Err(SignatureError::new(
                ErrorKind::Manifest,
                "signature config mediaType must be application/vnd.cncf.notary.signature",
            ));
        }
        if self.layers.len() != 1 {
            return Err(SignatureError::new(
                ErrorKind::Manifest,
                "signature manifest must contain exactly one layer",
            ));
        }
        let layer = &self.layers[0];
        layer.validate().map_err(manifest_error)?;
        if layer.media_type != JWS_MEDIA_TYPE && layer.media_type != COSE_MEDIA_TYPE {
            return Err(SignatureError::new(
                ErrorKind::Manifest,
                "signature layer mediaType must be application/jose+json or application/cose",
            ));
        }
        self.subject.validate().map_err(manifest_error)?;
        let Some(thumbprints) = self.annotations.get(THUMBPRINT_ANNOTATION) else {
            return Err(SignatureError::new(
                ErrorKind::Manifest,
                "signature manifest is missing io.cncf.notary.x509chain.thumbprint#S256",
            ));
        };
        parse_thumbprint_annotation(thumbprints)?;
        Ok(())
    }

    /// SHA-256 fingerprints from the thumbprint annotation, uppercase hex, leaf first.
    pub fn thumbprints(&self) -> Result<Vec<String>, SignatureError> {
        let raw = self.annotations.get(THUMBPRINT_ANNOTATION).ok_or_else(|| {
            SignatureError::new(
                ErrorKind::Manifest,
                "signature manifest is missing io.cncf.notary.x509chain.thumbprint#S256",
            )
        })?;
        parse_thumbprint_annotation(raw)
    }
}

/// SHA-256 fingerprint of a DER certificate, uppercase hex.
pub fn certificate_sha256_thumbprint(der: &[u8]) -> String {
    hex_encode(&Sha256::digest(der))
}

/// JSON array string of certificate thumbprints, leaf first.
pub fn thumbprint_annotation(chain: &[impl AsRef<[u8]>]) -> Result<String, SignatureError> {
    let prints: Vec<String> = chain
        .iter()
        .map(|der| certificate_sha256_thumbprint(der.as_ref()))
        .collect();
    serde_json::to_string(&prints).map_err(|err| {
        SignatureError::new(
            ErrorKind::Manifest,
            format!("failed to encode thumbprint annotation: {err}"),
        )
    })
}

/// `sha256:` digest of arbitrary bytes, lowercase hex.
pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_encode_lower(&Sha256::digest(bytes)))
}

/// Build a signature manifest for an envelope and certificate chain.
pub fn signature_manifest(
    subject: &Descriptor,
    envelope_media_type: &str,
    envelope: &[u8],
    certificate_chain: &[impl AsRef<[u8]>],
) -> Result<SignatureManifest, SignatureError> {
    subject.validate().map_err(manifest_error)?;
    if envelope_media_type != JWS_MEDIA_TYPE && envelope_media_type != COSE_MEDIA_TYPE {
        return Err(SignatureError::new(
            ErrorKind::Manifest,
            "signature envelope media type must be application/jose+json or application/cose",
        ));
    }
    if certificate_chain.is_empty() {
        return Err(SignatureError::new(
            ErrorKind::Manifest,
            "certificate chain is empty",
        ));
    }
    let size = i64::try_from(envelope.len())
        .map_err(|_| SignatureError::new(ErrorKind::Manifest, "signature envelope is too large"))?;
    let mut annotations = BTreeMap::new();
    annotations.insert(
        THUMBPRINT_ANNOTATION.to_string(),
        thumbprint_annotation(certificate_chain)?,
    );
    let manifest = SignatureManifest {
        schema_version: 2,
        media_type: OCI_MANIFEST_MEDIA_TYPE.to_string(),
        artifact_type: Some(SIGNATURE_ARTIFACT_TYPE.to_string()),
        config: Descriptor {
            media_type: SIGNATURE_CONFIG_MEDIA_TYPE.to_string(),
            digest: SIGNATURE_CONFIG_DIGEST.to_string(),
            size: SIGNATURE_CONFIG_SIZE,
            artifact_type: None,
            annotations: None,
        },
        layers: vec![Descriptor {
            media_type: envelope_media_type.to_string(),
            digest: sha256_digest(envelope),
            size,
            artifact_type: None,
            annotations: None,
        }],
        subject: subject.clone(),
        annotations,
    };
    manifest.validate()?;
    Ok(manifest)
}

pub(crate) fn parse_thumbprint_annotation(raw: &str) -> Result<Vec<String>, SignatureError> {
    let values: Vec<String> = serde_json::from_str(raw).map_err(|_| {
        SignatureError::new(
            ErrorKind::Manifest,
            "thumbprint annotation is not a JSON array of strings",
        )
    })?;
    if values.is_empty() {
        return Err(SignatureError::new(
            ErrorKind::Manifest,
            "thumbprint annotation is empty",
        ));
    }
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(SignatureError::new(
                ErrorKind::Manifest,
                "thumbprint annotation entry is not a SHA-256 hex fingerprint",
            ));
        }
        normalized.push(value.to_ascii_uppercase());
    }
    Ok(normalized)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_encode_lower(bytes: &[u8]) -> String {
    hex_encode(bytes).to_ascii_lowercase()
}

fn manifest_error(error: SignatureError) -> SignatureError {
    SignatureError::new(ErrorKind::Manifest, error.to_string())
}
