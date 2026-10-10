//! Sign, verify, and referrer selection against ephemeral certificates.

use std::collections::BTreeMap;

use base64::Engine;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use time::OffsetDateTime;

use super::manifest::{
    JWS_MEDIA_TYPE, SIGNATURE_ARTIFACT_TYPE, THUMBPRINT_ANNOTATION, signature_manifest,
};
use super::payload::{Descriptor, Payload};
use super::policy::{SignatureVerification, TrustPolicyStatement, VerificationLevel};
use super::referrers::{ReferrerDescriptor, filter_referrers_for_policy, parse_referrers_index};
use super::{
    COSE_MEDIA_TYPE, SignedAttributes, Verification, VerifyInput, sign_cose, sign_jws, verify,
};

const SIGNED_AT: i64 = 1_700_000_000;

fn window(not_before: i64, not_after: i64) -> (OffsetDateTime, OffsetDateTime) {
    (
        OffsetDateTime::from_unix_timestamp(not_before).unwrap(),
        OffsetDateTime::from_unix_timestamp(not_after).unwrap(),
    )
}

struct Issued {
    pkcs8: Vec<u8>,
    chain: Vec<Vec<u8>>,
    root: Vec<u8>,
}

fn issue(not_before: i64, not_after: i64) -> Issued {
    let (start, end) = window(not_before, not_after);
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.not_before = start;
    ca_params.not_after = end;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    leaf_params.not_before = start;
    leaf_params.not_after = end;
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "Test Leaf");
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    Issued {
        pkcs8: leaf_key.serialize_der(),
        chain: vec![leaf.der().to_vec(), ca.der().to_vec()],
        root: ca.der().to_vec(),
    }
}

fn payload() -> Payload {
    Payload {
        target_artifact: Descriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            digest: "sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333"
                .into(),
            size: 16724,
            artifact_type: None,
            annotations: None,
        },
    }
}

fn policy() -> TrustPolicyStatement {
    TrustPolicyStatement {
        name: "test".into(),
        registry_scopes: vec!["*".into()],
        signature_verification: SignatureVerification {
            level: VerificationLevel::Strict,
            verification_override: None,
            verify_timestamp: None,
        },
        trust_stores: Some(vec!["ca:test".into()]),
        trusted_identities: Some(vec!["*".into()]),
    }
}

fn anchors(root: &[u8]) -> BTreeMap<String, Vec<Vec<u8>>> {
    let mut anchors = BTreeMap::new();
    anchors.insert("ca:test".into(), vec![root.to_vec()]);
    anchors
}

fn verify_envelope(envelope: &[u8], media_type: &str, issued: &Issued) -> Verification {
    verify(&VerifyInput {
        envelope,
        media_type,
        policy: &policy(),
        trust_anchors: &anchors(&issued.root),
        verify_at: SIGNED_AT + 10,
        expected_artifact: Some(&payload().target_artifact),
    })
    .unwrap()
}

#[test]
fn jws_and_cose_round_trip() {
    let issued = issue(SIGNED_AT - 60, SIGNED_AT + 86_400);
    let attributes = SignedAttributes::x509(SIGNED_AT);
    let subject = payload();
    let jws = sign_jws(
        &subject,
        &issued.pkcs8,
        &issued.chain,
        &attributes,
        Some("oci-util/0.1.7"),
    )
    .unwrap();
    match verify_envelope(&jws, JWS_MEDIA_TYPE, &issued) {
        Verification::Verified { payload, .. } => assert_eq!(payload, subject),
        other => panic!("jws was not verified: {other:?}"),
    }
    let cose = sign_cose(&subject, &issued.pkcs8, &issued.chain, &attributes, None).unwrap();
    match verify_envelope(&cose, COSE_MEDIA_TYPE, &issued) {
        Verification::Verified { payload, .. } => assert_eq!(payload, subject),
        other => panic!("cose was not verified: {other:?}"),
    }
    let manifest = signature_manifest(
        &subject.target_artifact,
        JWS_MEDIA_TYPE,
        &jws,
        &issued.chain,
    )
    .unwrap();
    assert_eq!(manifest.layers[0].media_type, JWS_MEDIA_TYPE);
    assert!(manifest.annotations.contains_key(THUMBPRINT_ANNOTATION));
}

#[test]
fn tampered_jws_payload_fails() {
    let issued = issue(SIGNED_AT - 60, SIGNED_AT + 86_400);
    let mut jws: serde_json::Value = serde_json::from_slice(
        &sign_jws(
            &payload(),
            &issued.pkcs8,
            &issued.chain,
            &SignedAttributes::x509(SIGNED_AT),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    jws["payload"] = serde_json::Value::String("AAAA".into());
    let bytes = serde_json::to_vec(&jws).unwrap();
    let error = verify(&VerifyInput {
        envelope: &bytes,
        media_type: JWS_MEDIA_TYPE,
        policy: &policy(),
        trust_anchors: &anchors(&issued.root),
        verify_at: SIGNED_AT + 10,
        expected_artifact: None,
    })
    .unwrap_err();
    assert_eq!(error.kind(), super::ErrorKind::Signature);
}

#[test]
fn hmac_alg_is_rejected() {
    let issued = issue(SIGNED_AT - 60, SIGNED_AT + 86_400);
    let jws = sign_jws(
        &payload(),
        &issued.pkcs8,
        &issued.chain,
        &SignedAttributes::x509(SIGNED_AT),
        None,
    )
    .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&jws).unwrap();
    let protected = value["protected"].as_str().unwrap().to_string();
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(protected)
        .unwrap();
    let mut header: serde_json::Value = serde_json::from_slice(&header).unwrap();
    header["alg"] = serde_json::Value::String("HS256".into());
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).unwrap());
    value["protected"] = serde_json::Value::String(encoded);
    let error = verify(&VerifyInput {
        envelope: &serde_json::to_vec(&value).unwrap(),
        media_type: JWS_MEDIA_TYPE,
        policy: &policy(),
        trust_anchors: &anchors(&issued.root),
        verify_at: SIGNED_AT + 10,
        expected_artifact: None,
    })
    .unwrap_err();
    assert_eq!(error.kind(), super::ErrorKind::Algorithm);
}

#[test]
fn expired_certificate_is_rejected_at_signing() {
    let issued = issue(SIGNED_AT - 120, SIGNED_AT - 60);
    let error = sign_jws(
        &payload(),
        &issued.pkcs8,
        &issued.chain,
        &SignedAttributes::x509(SIGNED_AT),
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind(), super::ErrorKind::Certificate);
}

#[test]
fn referrers_filter_keeps_a_matching_thumbprint() {
    let issued = issue(SIGNED_AT - 60, SIGNED_AT + 86_400);
    let mut manifest = signature_manifest(
        &payload().target_artifact,
        JWS_MEDIA_TYPE,
        b"envelope",
        &issued.chain,
    )
    .unwrap();
    let thumb = manifest.annotations.remove(THUMBPRINT_ANNOTATION).unwrap();
    let index = format!(
        r#"{{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "size": 12,
                    "artifactType": "{SIGNATURE_ARTIFACT_TYPE}",
                    "annotations": {{ "{THUMBPRINT_ANNOTATION}": {thumb:?} }}
                }},
                {{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "size": 4,
                    "artifactType": "application/vnd.example.other"
                }}
            ]
        }}"#
    );
    let parsed = parse_referrers_index(index.as_bytes()).unwrap();
    let kept = filter_referrers_for_policy(
        &parsed.manifests,
        &policy_without_wildcard(),
        &[issued.root.as_slice()],
    )
    .unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].digest, parsed.manifests[0].digest);

    let other = ReferrerDescriptor {
        media_type: "application/vnd.oci.image.manifest.v1+json".into(),
        digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        size: 1,
        artifact_type: Some(SIGNATURE_ARTIFACT_TYPE.into()),
        annotations: None,
        platform: None,
        urls: None,
        data: None,
    };
    let others = [other];
    let none = filter_referrers_for_policy(
        &others,
        &policy_without_wildcard(),
        &[issued.root.as_slice()],
    )
    .unwrap();
    assert!(none.is_empty());
}

fn policy_without_wildcard() -> TrustPolicyStatement {
    let mut statement = policy();
    statement.trusted_identities = Some(vec!["x509.subject:C=US,ST=CA,O=Other".into()]);
    statement
}
