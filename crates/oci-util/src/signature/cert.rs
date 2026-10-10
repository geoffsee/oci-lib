//! Certificate chain checks from the Notary signature specification.

use std::collections::BTreeMap;

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{ParsedExtension, X509Extension};
use x509_parser::oid_registry::{
    OID_PKIX_ACCESS_DESCRIPTOR_OCSP, OID_PKIX_AUTHORITY_INFO_ACCESS, OID_X509_COMMON_NAME,
    OID_X509_COUNTRY_NAME, OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
    OID_X509_EXT_EXTENDED_KEY_USAGE, OID_X509_EXT_KEY_USAGE, OID_X509_LOCALITY_NAME,
    OID_X509_ORGANIZATION_NAME, OID_X509_ORGANIZATIONAL_UNIT, OID_X509_STATE_OR_PROVINCE_NAME,
};
use x509_parser::x509::X509Name;

use super::crypto::{self, PublicKey};
use super::error::{ErrorKind, SignatureError};

/// A parsed leaf-first chain.
pub(crate) struct ParsedChain {
    pub(crate) leaf_key: PublicKey,
}

pub(crate) fn parse_chain(ders: &[impl AsRef<[u8]>]) -> Result<Vec<Vec<u8>>, SignatureError> {
    if ders.is_empty() {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "certificate chain is empty",
        ));
    }
    Ok(ders.iter().map(|der| der.as_ref().to_vec()).collect())
}

/// Structural checks used at signing time. `at` is the signing time or authentic signing time.
pub(crate) fn check_chain_for_signing(
    ders: &[impl AsRef<[u8]>],
    at: i64,
    leaf_key: &PublicKey,
) -> Result<(), SignatureError> {
    let owned = parse_chain(ders)?;
    let parsed = parse_all(&owned)?;
    for cert in &parsed {
        crypto::reject_sha1(cert)?;
    }
    validate_structure(&parsed)?;
    require_valid_at(&parsed, at)?;
    let actual = crypto::public_key_from_cert(&parsed[0])?;
    if !actual.matches(leaf_key) {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "leaf certificate does not match the signing key",
        ));
    }
    let _ = actual.algorithm()?;
    Ok(())
}

pub(crate) fn load_chain(ders: &[Vec<u8>]) -> Result<ParsedChain, SignatureError> {
    let parsed = parse_all(ders)?;
    for cert in &parsed {
        crypto::reject_sha1(cert)?;
    }
    let leaf_key = crypto::public_key_from_cert(&parsed[0])?;
    let _ = leaf_key.algorithm()?;
    Ok(ParsedChain { leaf_key })
}

/// Authenticity checks other than trust anchors and trusted identities.
pub(crate) fn validate_authenticity(
    ders: &[Vec<u8>],
    at_signing: i64,
) -> Result<(), SignatureError> {
    let parsed = parse_all(ders)?;
    validate_structure(&parsed)?;
    require_valid_at(&parsed, at_signing)
}

pub(crate) fn require_valid_at(
    certs: &[X509Certificate<'_>],
    at: i64,
) -> Result<(), SignatureError> {
    for cert in certs {
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        if at < not_before || at > not_after {
            return Err(SignatureError::new(
                ErrorKind::Certificate,
                "certificate is outside its validity period (expired or not yet valid)",
            ));
        }
    }
    Ok(())
}

pub(crate) fn chain_expired_at(ders: &[Vec<u8>], at: i64) -> Result<bool, SignatureError> {
    let parsed = parse_all(ders)?;
    Ok(parsed.iter().any(|cert| {
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        at < not_before || at > not_after
    }))
}

pub(crate) fn require_valid_ders(ders: &[Vec<u8>], at: i64) -> Result<(), SignatureError> {
    let parsed = parse_all(ders)?;
    require_valid_at(&parsed, at)
}

/// True when any certificate advertises OCSP or a CRL distribution point.
pub(crate) fn revocation_info_present(ders: &[Vec<u8>]) -> Result<bool, SignatureError> {
    let parsed = parse_all(ders)?;
    for cert in &parsed {
        for ext in cert.extensions() {
            if ext.oid == OID_X509_EXT_CRL_DISTRIBUTION_POINTS {
                return Ok(true);
            }
            if ext.oid == OID_PKIX_AUTHORITY_INFO_ACCESS {
                match ext.parsed_extension() {
                    ParsedExtension::AuthorityInfoAccess(info) => {
                        if info
                            .accessdescs
                            .iter()
                            .any(|desc| desc.access_method == OID_PKIX_ACCESS_DESCRIPTOR_OCSP)
                        {
                            return Ok(true);
                        }
                    }
                    ParsedExtension::ParseError { .. }
                    | ParsedExtension::UnsupportedExtension { .. } => {
                        return Err(SignatureError::new(
                            ErrorKind::Certificate,
                            "authority information access extension could not be parsed",
                        ));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(false)
}

pub(crate) fn leaf_subject_matches(
    ders: &[Vec<u8>],
    identity: &BTreeMap<String, String>,
) -> Result<bool, SignatureError> {
    let parsed = parse_all(ders)?;
    Ok(identity_matches(parsed[0].subject(), identity))
}

fn parse_all(ders: &[Vec<u8>]) -> Result<Vec<X509Certificate<'_>>, SignatureError> {
    ders.iter().map(|der| crypto::parse_cert(der)).collect()
}

fn validate_structure(certs: &[X509Certificate<'_>]) -> Result<(), SignatureError> {
    let refs: Vec<&X509Certificate<'_>> = certs.iter().collect();
    let last = refs.len() - 1;
    for (index, cert) in refs.iter().enumerate() {
        let parent_key = if index == last {
            if !names_equal(cert.subject(), cert.issuer()) {
                return Err(SignatureError::new(
                    ErrorKind::Certificate,
                    "root certificate is not self-issued",
                ));
            }
            crypto::public_key_from_cert(cert)?
        } else {
            let parent = refs[index + 1];
            if !names_equal(cert.issuer(), parent.subject()) {
                return Err(SignatureError::new(
                    ErrorKind::Certificate,
                    "certificate issuer does not match the next certificate subject",
                ));
            }
            crypto::public_key_from_cert(parent)?
        };
        crypto::verify_cert_signature(cert, &parent_key)?;
        if refs.len() == 1 || index == 0 {
            check_leaf(cert)?;
        } else {
            check_ca(cert, &refs, index)?;
        }
    }
    Ok(())
}

fn check_leaf(cert: &X509Certificate<'_>) -> Result<(), SignatureError> {
    if let Some(ext) = extension(cert, &OID_X509_EXT_BASIC_CONSTRAINTS)? {
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(constraints) => {
                if constraints.ca {
                    return Err(SignatureError::new(
                        ErrorKind::Certificate,
                        "leaf certificate is a CA",
                    ));
                }
            }
            _ => {
                return Err(SignatureError::new(
                    ErrorKind::Certificate,
                    "leaf basic constraints extension could not be parsed",
                ));
            }
        }
    }
    let key_usage = require_key_usage(cert, true)?;
    if !key_usage.digital_signature()
        || key_usage.key_encipherment()
        || key_usage.data_encipherment()
        || key_usage.key_agreement()
        || key_usage.key_cert_sign()
        || key_usage.crl_sign()
        || key_usage.encipher_only()
        || key_usage.decipher_only()
    {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "leaf key usage is not suitable for code signing",
        ));
    }
    if let Some(ext) = extension(cert, &OID_X509_EXT_EXTENDED_KEY_USAGE)? {
        match ext.parsed_extension() {
            ParsedExtension::ExtendedKeyUsage(usage) => {
                if usage.any
                    || usage.server_auth
                    || usage.client_auth
                    || usage.email_protection
                    || usage.time_stamping
                {
                    return Err(SignatureError::new(
                        ErrorKind::Certificate,
                        "leaf extended key usage is not suitable for code signing",
                    ));
                }
            }
            _ => {
                return Err(SignatureError::new(
                    ErrorKind::Certificate,
                    "leaf extended key usage extension could not be parsed",
                ));
            }
        }
    }
    Ok(())
}

fn check_ca(
    cert: &X509Certificate<'_>,
    chain: &[&X509Certificate<'_>],
    index: usize,
) -> Result<(), SignatureError> {
    let ext = extension(cert, &OID_X509_EXT_BASIC_CONSTRAINTS)?.ok_or_else(|| {
        SignatureError::new(
            ErrorKind::Certificate,
            "CA certificate is missing basic constraints",
        )
    })?;
    if !ext.critical {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "CA basic constraints extension is not critical",
        ));
    }
    let ParsedExtension::BasicConstraints(constraints) = ext.parsed_extension() else {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "CA basic constraints extension could not be parsed",
        ));
    };
    if !constraints.ca {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "intermediate certificate is not a CA",
        ));
    }
    if let Some(limit) = constraints.path_len_constraint {
        let below = intermediates_below(chain, index);
        if below > usize::try_from(limit).unwrap_or(usize::MAX) {
            return Err(SignatureError::new(
                ErrorKind::Certificate,
                "CA pathLenConstraint is exceeded",
            ));
        }
    }
    let key_usage = require_key_usage(cert, true)?;
    if !key_usage.key_cert_sign() {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "CA key usage is missing keyCertSign",
        ));
    }
    Ok(())
}

fn intermediates_below(chain: &[&X509Certificate<'_>], ca_index: usize) -> usize {
    chain
        .iter()
        .take(ca_index)
        .skip(1)
        .filter(|cert| !names_equal(cert.subject(), cert.issuer()))
        .count()
}

fn require_key_usage(
    cert: &X509Certificate<'_>,
    critical: bool,
) -> Result<x509_parser::extensions::KeyUsage, SignatureError> {
    let ext = extension(cert, &OID_X509_EXT_KEY_USAGE)?.ok_or_else(|| {
        SignatureError::new(ErrorKind::Certificate, "certificate is missing key usage")
    })?;
    if critical && !ext.critical {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "key usage extension is not critical",
        ));
    }
    match ext.parsed_extension() {
        ParsedExtension::KeyUsage(usage) => Ok(*usage),
        _ => Err(SignatureError::new(
            ErrorKind::Certificate,
            "key usage extension could not be parsed",
        )),
    }
}

fn extension<'a>(
    cert: &'a X509Certificate<'a>,
    oid: &x509_parser::der_parser::oid::Oid<'_>,
) -> Result<Option<&'a X509Extension<'a>>, SignatureError> {
    let mut found = None;
    for ext in cert.extensions() {
        if &ext.oid == oid {
            if found.is_some() {
                return Err(SignatureError::new(
                    ErrorKind::Certificate,
                    "certificate repeats basic constraints, key usage, or extended key usage",
                ));
            }
            found = Some(ext);
        }
    }
    Ok(found)
}

fn names_equal(left: &X509Name<'_>, right: &X509Name<'_>) -> bool {
    if left.as_raw() == right.as_raw() {
        return true;
    }
    name_pairs(left) == name_pairs(right)
}

fn name_pairs(name: &X509Name<'_>) -> Vec<(String, Vec<u8>)> {
    let mut pairs = Vec::new();
    for attr in name.iter_attributes() {
        pairs.push((
            attr.attr_type().to_id_string(),
            attr.attr_value().as_bytes().to_vec(),
        ));
    }
    pairs.sort();
    pairs
}

pub(crate) fn identity_matches(
    subject: &X509Name<'_>,
    identity: &BTreeMap<String, String>,
) -> bool {
    let mut present: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for attr in subject.iter_attributes() {
        let Some(short) = short_name(&attr.attr_type().to_id_string()) else {
            continue;
        };
        let Ok(value) = attr.as_str() else {
            continue;
        };
        present.entry(short).or_default().push(value.to_string());
    }
    identity.iter().all(|(kind, value)| {
        present
            .get(kind)
            .is_some_and(|values| values.iter().any(|candidate| candidate == value))
    })
}

fn short_name(oid: &str) -> Option<String> {
    if oid == OID_X509_COUNTRY_NAME.to_id_string() {
        Some("C".to_string())
    } else if oid == OID_X509_STATE_OR_PROVINCE_NAME.to_id_string() {
        Some("ST".to_string())
    } else if oid == OID_X509_LOCALITY_NAME.to_id_string() {
        Some("L".to_string())
    } else if oid == OID_X509_ORGANIZATION_NAME.to_id_string() {
        Some("O".to_string())
    } else if oid == OID_X509_ORGANIZATIONAL_UNIT.to_id_string() {
        Some("OU".to_string())
    } else if oid == OID_X509_COMMON_NAME.to_id_string() {
        Some("CN".to_string())
    } else {
        None
    }
}
