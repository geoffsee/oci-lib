//! Notary Project v1.1.0 signatures.
//!
//! The caller fetches registry bytes and supplies trust anchors. This module parses
//! payloads, JWS and COSE envelopes, certificate chains, trust policy, and OCI
//! referrers indexes. It does not speak HTTP. RFC 3161 timestamp tokens are
//! recognized and rejected closed.

mod attributes;
mod b64;
mod cert;
mod cose;
mod crypto;
mod error;
mod jws;
mod manifest;
mod payload;
mod policy;
mod referrers;
mod sign;
mod timeutil;
mod verify;

pub use attributes::{SignedAttributes, SigningScheme};
pub use error::{ErrorKind, SignatureError};
pub use manifest::{
    COSE_MEDIA_TYPE, JWS_MEDIA_TYPE, OCI_INDEX_MEDIA_TYPE, OCI_MANIFEST_MEDIA_TYPE,
    SIGNATURE_ARTIFACT_TYPE, SIGNATURE_CONFIG_BYTES, SIGNATURE_CONFIG_DIGEST,
    SIGNATURE_CONFIG_MEDIA_TYPE, SIGNATURE_CONFIG_SIZE, SignatureManifest, THUMBPRINT_ANNOTATION,
    certificate_sha256_thumbprint, sha256_digest, signature_manifest, thumbprint_annotation,
};
pub use payload::{Descriptor, NOTARY_ANNOTATION_PREFIX, PAYLOAD_MEDIA_TYPE, Payload};
pub use policy::{
    EffectivePolicy, SignatureVerification, TimestampVerification, TrustPolicyDocument,
    TrustPolicyStatement, ValidationAction, VerificationLevel, VerificationOverride,
    select_trust_policy,
};
pub use referrers::{
    ReferrerDescriptor, ReferrersIndex, filter_referrers_for_policy, parse_referrers_index,
    select_notary_referrers,
};
pub use sign::{sign_cose, sign_jws};
pub use verify::{Verification, VerifyInput, verify};

#[cfg(test)]
mod tests;
