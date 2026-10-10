//! Verify a Notary envelope against a trust policy, anchors, and a time.
//!
//! Verification does not fetch certificates, revocation data, or timestamp tokens.
//! A present timestamp countersignature fails closed because RFC 3161 is not
//! implemented. Absence of that header is allowed for `notary.x509` when timestamp
//! verification is not triggered and every certificate is inside its validity window.

use std::collections::BTreeMap;

use super::attributes::SigningScheme;
use super::cert;
use super::cose;
use super::error::{ErrorKind, SignatureError};
use super::jws;
use super::manifest::{COSE_MEDIA_TYPE, JWS_MEDIA_TYPE};
use super::payload::{Descriptor, Payload};
use super::policy::{
    EffectivePolicy, TimestampVerification, TrustPolicyStatement, ValidationAction,
    VerificationLevel, parse_identities,
};

/// Inputs to [`verify`]. The caller has already fetched the envelope and anchors.
pub struct VerifyInput<'a> {
    /// JWS or COSE envelope bytes.
    pub envelope: &'a [u8],
    /// `application/jose+json` or `application/cose`.
    pub media_type: &'a str,
    /// Applicable trust policy statement.
    pub policy: &'a TrustPolicyStatement,
    /// Trust anchors keyed by `{type}:{name}`, DER encoded.
    pub trust_anchors: &'a BTreeMap<String, Vec<Vec<u8>>>,
    /// Verification time, Unix seconds.
    pub verify_at: i64,
    /// Optional artifact descriptor that `targetArtifact` must match.
    pub expected_artifact: Option<&'a Descriptor>,
}

/// Successful verification. Logged policy failures are observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// The trust policy level is `skip`. The envelope was not parsed.
    Skipped,
    /// Integrity succeeded and every enforced check succeeded.
    Verified {
        /// Signed payload.
        payload: Payload,
        /// Signing scheme from the protected header.
        scheme: SigningScheme,
        /// Failures that the policy records instead of rejecting.
        observations: Vec<String>,
    },
}

struct ParsedSignature {
    payload: Payload,
    scheme: SigningScheme,
    signing_time: Option<i64>,
    authentic_signing_time: Option<i64>,
    expiry: Option<i64>,
    certificates: Vec<Vec<u8>>,
    timestamp_present: bool,
}

/// Verify `input` as a pure function of the envelope, policy, anchors, and time.
pub fn verify(input: &VerifyInput<'_>) -> Result<Verification, SignatureError> {
    let effective = input.policy.effective()?;
    if effective.level == VerificationLevel::Skip {
        return Ok(Verification::Skipped);
    }
    let parsed = parse_and_check_integrity(input)?;
    if parsed.timestamp_present {
        return Err(SignatureError::new(
            ErrorKind::Timestamp,
            "RFC 3161 timestamp countersignature is present but this crate does not verify timestamp tokens; verification failed closed",
        ));
    }
    let mut observations = Vec::new();
    apply(
        effective.authenticity,
        authenticate(&parsed, input),
        &mut observations,
    )?;
    apply(
        effective.expiry,
        check_expiry(&parsed, input.verify_at),
        &mut observations,
    )?;
    apply(
        effective.authentic_timestamp,
        check_authentic_timestamp(&parsed, input, &effective),
        &mut observations,
    )?;
    apply(
        effective.revocation,
        check_revocation(&parsed),
        &mut observations,
    )?;
    Ok(Verification::Verified {
        payload: parsed.payload,
        scheme: parsed.scheme,
        observations,
    })
}

fn parse_and_check_integrity(input: &VerifyInput<'_>) -> Result<ParsedSignature, SignatureError> {
    let (
        payload_bytes,
        algorithm,
        scheme,
        signing_time,
        authentic,
        expiry,
        certificates,
        signing_input,
        signature,
        timestamp_present,
    ) = match input.media_type {
        JWS_MEDIA_TYPE => {
            let envelope = jws::parse(input.envelope)?;
            (
                envelope.payload,
                envelope.attributes.algorithm,
                envelope.attributes.scheme,
                envelope.attributes.signing_time,
                envelope.attributes.authentic_signing_time,
                envelope.attributes.expiry,
                envelope.certificates,
                envelope.signing_input,
                envelope.signature,
                envelope.timestamp_present,
            )
        }
        COSE_MEDIA_TYPE => {
            let envelope = cose::parse(input.envelope)?;
            (
                envelope.payload,
                envelope.attributes.algorithm,
                envelope.attributes.scheme,
                envelope.attributes.signing_time,
                envelope.attributes.authentic_signing_time,
                envelope.attributes.expiry,
                envelope.certificates,
                envelope.signing_input,
                envelope.signature,
                envelope.timestamp_present,
            )
        }
        _ => {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                "signature media type must be application/jose+json or application/cose",
            ));
        }
    };
    let loaded = cert::load_chain(&certificates)?;
    loaded
        .leaf_key
        .verify(algorithm, &signing_input, &signature)?;
    let payload = Payload::from_bytes(&payload_bytes)?;
    if let Some(expected) = input.expected_artifact {
        artifact_matches(expected, &payload.target_artifact)?;
    }
    Ok(ParsedSignature {
        payload,
        scheme,
        signing_time,
        authentic_signing_time: authentic,
        expiry,
        certificates,
        timestamp_present,
    })
}

fn authenticate(parsed: &ParsedSignature, input: &VerifyInput<'_>) -> Result<(), SignatureError> {
    let at_signing = match parsed.scheme {
        SigningScheme::X509 => parsed.signing_time.ok_or_else(|| {
            SignatureError::new(
                ErrorKind::Encoding,
                "signingTime is required for notary.x509",
            )
        })?,
        SigningScheme::X509SigningAuthority => parsed.authentic_signing_time.ok_or_else(|| {
            SignatureError::new(
                ErrorKind::Encoding,
                "authenticSigningTime is required for notary.x509.signingAuthority",
            )
        })?,
    };
    cert::validate_authenticity(&parsed.certificates, at_signing)?;
    let root = parsed
        .certificates
        .last()
        .ok_or_else(|| SignatureError::new(ErrorKind::Certificate, "certificate chain is empty"))?;
    let prefix = match parsed.scheme {
        SigningScheme::X509 => "ca:",
        SigningScheme::X509SigningAuthority => "signingAuthority:",
    };
    let mut matched = false;
    if let Some(stores) = &input.policy.trust_stores {
        for store in stores {
            if !store.starts_with(prefix) {
                continue;
            }
            if let Some(anchors) = input.trust_anchors.get(store) {
                if anchors
                    .iter()
                    .any(|anchor| anchor.as_slice() == root.as_slice())
                {
                    matched = true;
                    break;
                }
            }
        }
    }
    if !matched {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "certificate chain does not end at a configured trust anchor",
        ));
    }
    let identities = parse_identities(input.policy.trusted_identities.as_deref().unwrap_or(&[]))?;
    if identities.is_empty() {
        return Ok(());
    }
    for identity in &identities {
        if cert::leaf_subject_matches(&parsed.certificates, identity)? {
            return Ok(());
        }
    }
    Err(SignatureError::new(
        ErrorKind::Certificate,
        "leaf certificate subject does not match a trusted identity",
    ))
}

fn check_expiry(parsed: &ParsedSignature, verify_at: i64) -> Result<(), SignatureError> {
    if let Some(expiry) = parsed.expiry {
        if verify_at >= expiry {
            return Err(SignatureError::new(
                ErrorKind::Certificate,
                "signature expiry time has passed",
            ));
        }
    }
    Ok(())
}

fn check_authentic_timestamp(
    parsed: &ParsedSignature,
    input: &VerifyInput<'_>,
    effective: &EffectivePolicy,
) -> Result<(), SignatureError> {
    match parsed.scheme {
        SigningScheme::X509 => {
            if timestamp_triggered(parsed, input, effective)? {
                Err(SignatureError::new(
                    ErrorKind::Timestamp,
                    "timestamp countersignature is required by the trust policy but is absent",
                ))
            } else {
                cert::require_valid_ders(&parsed.certificates, input.verify_at)
            }
        }
        SigningScheme::X509SigningAuthority => {
            let at = parsed.authentic_signing_time.ok_or_else(|| {
                SignatureError::new(
                    ErrorKind::Encoding,
                    "authenticSigningTime is required for notary.x509.signingAuthority",
                )
            })?;
            cert::require_valid_ders(&parsed.certificates, at)
        }
    }
}

fn timestamp_triggered(
    parsed: &ParsedSignature,
    input: &VerifyInput<'_>,
    effective: &EffectivePolicy,
) -> Result<bool, SignatureError> {
    if parsed.scheme != SigningScheme::X509 || !effective.has_tsa_store {
        return Ok(false);
    }
    match effective.verify_timestamp {
        TimestampVerification::Always => Ok(true),
        TimestampVerification::AfterCertExpiry => {
            cert::chain_expired_at(&parsed.certificates, input.verify_at)
        }
    }
}

fn check_revocation(parsed: &ParsedSignature) -> Result<(), SignatureError> {
    if cert::revocation_info_present(&parsed.certificates)? {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "revocation status is unavailable because this crate does not fetch OCSP or CRLs",
        ));
    }
    Ok(())
}

fn artifact_matches(expected: &Descriptor, actual: &Descriptor) -> Result<(), SignatureError> {
    if expected.media_type != actual.media_type
        || expected.size != actual.size
        || !expected.digest.eq_ignore_ascii_case(&actual.digest)
    {
        return Err(SignatureError::new(
            ErrorKind::Payload,
            "payload targetArtifact does not match the expected artifact",
        ));
    }
    if let Some(expected_type) = &expected.artifact_type {
        if actual.artifact_type.as_ref() != Some(expected_type) {
            return Err(SignatureError::new(
                ErrorKind::Payload,
                "payload targetArtifact artifactType does not match",
            ));
        }
    }
    if let Some(expected_annotations) = &expected.annotations {
        for (key, value) in expected_annotations {
            let found = actual
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(key));
            if found != Some(value) {
                return Err(SignatureError::new(
                    ErrorKind::Payload,
                    "payload targetArtifact annotations do not match",
                ));
            }
        }
    }
    Ok(())
}

fn apply(
    action: ValidationAction,
    result: Result<(), SignatureError>,
    observations: &mut Vec<String>,
) -> Result<(), SignatureError> {
    match (action, result) {
        (_, Ok(())) => Ok(()),
        (ValidationAction::Enforce, Err(error)) => Err(error),
        (ValidationAction::Log, Err(error)) => {
            observations.push(error.to_string());
            Ok(())
        }
        (ValidationAction::Skip, Err(_)) => Ok(()),
    }
}
