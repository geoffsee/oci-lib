//! OCI referrers index parsing and Notary signature selection.
//!
//! Fetching the index and the signature blobs is the caller's job.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::error::{ErrorKind, SignatureError};
use super::manifest::{
    OCI_INDEX_MEDIA_TYPE, SIGNATURE_ARTIFACT_TYPE, THUMBPRINT_ANNOTATION,
    certificate_sha256_thumbprint, parse_thumbprint_annotation,
};
use super::payload::validate_digest;
use super::policy::TrustPolicyStatement;

/// OCI image index returned by the referrers API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferrersIndex {
    /// Must be `2`.
    #[serde(rename = "schemaVersion")]
    pub schema_version: i32,
    /// Optional index media type.
    #[serde(rename = "mediaType", default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Manifest descriptors.
    pub manifests: Vec<ReferrerDescriptor>,
    /// Optional index annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// One manifest in a referrers index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferrerDescriptor {
    /// Manifest media type.
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// Manifest digest.
    pub digest: String,
    /// Manifest size in bytes.
    pub size: i64,
    /// Artifact type. Notary signatures use [`SIGNATURE_ARTIFACT_TYPE`].
    #[serde(
        rename = "artifactType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub artifact_type: Option<String>,
    /// Manifest annotations, including the certificate thumbprint annotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Ignored OCI descriptor field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<serde_json::Value>,
    /// Ignored OCI descriptor field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<serde_json::Value>,
    /// Ignored OCI descriptor field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Parse an OCI referrers index.
pub fn parse_referrers_index(bytes: &[u8]) -> Result<ReferrersIndex, SignatureError> {
    let index: ReferrersIndex = serde_json::from_slice(bytes).map_err(|err| {
        SignatureError::new(
            ErrorKind::Referrers,
            format!("invalid referrers index: {err}"),
        )
    })?;
    if index.schema_version != 2 {
        return Err(SignatureError::new(
            ErrorKind::Referrers,
            "referrers index schemaVersion must be 2",
        ));
    }
    if let Some(media_type) = &index.media_type {
        if media_type != OCI_INDEX_MEDIA_TYPE {
            return Err(SignatureError::new(
                ErrorKind::Referrers,
                "referrers index mediaType is not an OCI image index",
            ));
        }
    }
    for manifest in &index.manifests {
        if manifest.media_type.is_empty() {
            return Err(SignatureError::new(
                ErrorKind::Referrers,
                "referrer mediaType is empty",
            ));
        }
        validate_digest(&manifest.digest)
            .map_err(|err| SignatureError::new(ErrorKind::Referrers, err.to_string()))?;
        if manifest.size < 0 {
            return Err(SignatureError::new(
                ErrorKind::Referrers,
                "referrer size is negative",
            ));
        }
    }
    Ok(index)
}

/// Manifests whose artifact type is a Notary signature.
pub fn select_notary_referrers(index: &ReferrersIndex) -> Vec<&ReferrerDescriptor> {
    index
        .manifests
        .iter()
        .filter(|manifest| manifest.artifact_type.as_deref() == Some(SIGNATURE_ARTIFACT_TYPE))
        .collect()
}

/// Keep Notary referrers whose thumbprint annotation meets the trust policy.
///
/// When identities are `*` or the level is `skip`, every Notary referrer is returned.
/// Otherwise a referrer is kept when its thumbprint annotation shares a SHA-256
/// fingerprint with `trusted_certificates` (the caller-supplied anchors or chain).
pub fn filter_referrers_for_policy<'a>(
    referrers: &'a [ReferrerDescriptor],
    policy: &TrustPolicyStatement,
    trusted_certificates: &[impl AsRef<[u8]>],
) -> Result<Vec<&'a ReferrerDescriptor>, SignatureError> {
    policy.validate()?;
    let notary: Vec<&ReferrerDescriptor> = referrers
        .iter()
        .filter(|manifest| manifest.artifact_type.as_deref() == Some(SIGNATURE_ARTIFACT_TYPE))
        .collect();
    if policy.identities_unconstrained()? {
        return Ok(notary);
    }
    let trusted: Vec<String> = trusted_certificates
        .iter()
        .map(|der| certificate_sha256_thumbprint(der.as_ref()))
        .collect();
    let mut matched = Vec::new();
    for referrer in notary {
        let Some(raw) = referrer
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(THUMBPRINT_ANNOTATION))
        else {
            continue;
        };
        let prints = parse_thumbprint_annotation(raw)
            .map_err(|err| SignatureError::new(ErrorKind::Referrers, err.to_string()))?;
        if prints
            .iter()
            .any(|print| trusted.iter().any(|anchor| anchor == print))
        {
            matched.push(referrer);
        }
    }
    Ok(matched)
}
