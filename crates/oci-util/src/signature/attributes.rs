//! Signed Notary attributes shared by JWS and COSE envelopes.

use super::crypto::Algorithm;
use super::error::{ErrorKind, SignatureError};
use super::payload::PAYLOAD_MEDIA_TYPE;
use super::timeutil;

pub const SIGNING_SCHEME: &str = "io.cncf.notary.signingScheme";
pub const SIGNING_TIME: &str = "io.cncf.notary.signingTime";
pub const AUTHENTIC_SIGNING_TIME: &str = "io.cncf.notary.authenticSigningTime";
pub const EXPIRY: &str = "io.cncf.notary.expiry";
pub const TIMESTAMP_SIGNATURE: &str = "io.cncf.notary.timestampSignature";
pub const TIMESTAMP_ALIAS: &str = "io.cncf.notary.timestamp";
pub const SIGNING_AGENT: &str = "io.cncf.notary.signingAgent";
pub const VERIFICATION_PLUGIN: &str = "io.cncf.notary.verificationPlugin";
pub const VERIFICATION_PLUGIN_MIN_VERSION: &str = "io.cncf.notary.verificationPluginMinVersion";

pub const SCHEME_X509: &str = "notary.x509";
pub const SCHEME_SIGNING_AUTHORITY: &str = "notary.x509.signingAuthority";

/// Notary signing scheme carried in the protected header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningScheme {
    /// `notary.x509`. `signingTime` is required and is not a trusted time.
    X509,
    /// `notary.x509.signingAuthority`. `authenticSigningTime` is required and critical.
    X509SigningAuthority,
}

impl SigningScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X509 => SCHEME_X509,
            Self::X509SigningAuthority => SCHEME_SIGNING_AUTHORITY,
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, SignatureError> {
        match value {
            SCHEME_X509 => Ok(Self::X509),
            SCHEME_SIGNING_AUTHORITY => Ok(Self::X509SigningAuthority),
            other => Err(SignatureError::new(
                ErrorKind::Encoding,
                format!("unsupported Notary signing scheme `{other}`"),
            )),
        }
    }
}

/// Signed attribute inputs for [`crate::signature::sign_jws`] and [`crate::signature::sign_cose`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAttributes {
    /// Signing scheme. Selects which time header is required.
    pub scheme: SigningScheme,
    /// Unix seconds. Required for [`SigningScheme::X509`] and rejected otherwise.
    pub signing_time: Option<i64>,
    /// Unix seconds. Required for [`SigningScheme::X509SigningAuthority`] and rejected otherwise.
    pub authentic_signing_time: Option<i64>,
    /// Optional expiry, Unix seconds. Critical when present.
    pub expiry: Option<i64>,
}

impl SignedAttributes {
    /// Attributes for `notary.x509`.
    pub fn x509(signing_time: i64) -> Self {
        Self {
            scheme: SigningScheme::X509,
            signing_time: Some(signing_time),
            authentic_signing_time: None,
            expiry: None,
        }
    }

    /// Attributes for `notary.x509.signingAuthority`.
    pub fn signing_authority(authentic_signing_time: i64) -> Self {
        Self {
            scheme: SigningScheme::X509SigningAuthority,
            signing_time: None,
            authentic_signing_time: Some(authentic_signing_time),
            expiry: None,
        }
    }

    /// Set the optional expiry time.
    pub fn with_expiry(mut self, expiry: i64) -> Self {
        self.expiry = Some(expiry);
        self
    }

    pub(crate) fn validate(&self) -> Result<(), SignatureError> {
        match self.scheme {
            SigningScheme::X509 => {
                if self.signing_time.is_none() {
                    return Err(SignatureError::new(
                        ErrorKind::Encoding,
                        "signingTime is required for notary.x509",
                    ));
                }
                if self.authentic_signing_time.is_some() {
                    return Err(SignatureError::new(
                        ErrorKind::Encoding,
                        "authenticSigningTime is only valid for notary.x509.signingAuthority",
                    ));
                }
            }
            SigningScheme::X509SigningAuthority => {
                if self.authentic_signing_time.is_none() {
                    return Err(SignatureError::new(
                        ErrorKind::Encoding,
                        "authenticSigningTime is required for notary.x509.signingAuthority",
                    ));
                }
                if self.signing_time.is_some() {
                    return Err(SignatureError::new(
                        ErrorKind::Encoding,
                        "signingTime is only valid for notary.x509",
                    ));
                }
            }
        }
        if let Some(time) = self.signing_time {
            let _ = timeutil::format_rfc3339(time)?;
        }
        if let Some(time) = self.authentic_signing_time {
            let _ = timeutil::format_rfc3339(time)?;
        }
        if let Some(time) = self.expiry {
            let _ = timeutil::format_rfc3339(time)?;
        }
        Ok(())
    }

    /// Time used to check certificate validity while signing.
    pub(crate) fn certificate_time(&self) -> Result<i64, SignatureError> {
        self.validate()?;
        match self.scheme {
            SigningScheme::X509 => self
                .signing_time
                .ok_or_else(|| SignatureError::new(ErrorKind::Encoding, "signingTime is required")),
            SigningScheme::X509SigningAuthority => self.authentic_signing_time.ok_or_else(|| {
                SignatureError::new(ErrorKind::Encoding, "authenticSigningTime is required")
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedAttributes {
    pub(crate) algorithm: Algorithm,
    pub(crate) scheme: SigningScheme,
    pub(crate) signing_time: Option<i64>,
    pub(crate) authentic_signing_time: Option<i64>,
    pub(crate) expiry: Option<i64>,
}

pub(crate) fn expected_crit(authentic: bool, expiry: bool) -> Vec<&'static str> {
    let mut names = vec![SIGNING_SCHEME];
    if authentic {
        names.push(AUTHENTIC_SIGNING_TIME);
    }
    if expiry {
        names.push(EXPIRY);
    }
    names
}

pub(crate) fn check_crit(
    crit: &[String],
    authentic: bool,
    expiry: bool,
) -> Result<(), SignatureError> {
    let expected = expected_crit(authentic, expiry);
    if crit.len() != expected.len()
        || expected
            .iter()
            .any(|name| !crit.iter().any(|item| item == name))
    {
        if crit.iter().any(|name| name == SIGNING_TIME) {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                "signingTime is not a critical header",
            ));
        }
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "crit does not list exactly the critical Notary headers that are present",
        ));
    }
    let mut seen = Vec::new();
    for name in crit {
        if seen.contains(name) {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                "crit repeats a critical header",
            ));
        }
        seen.push(name.clone());
        if is_registered_header(name) {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                format!("crit lists registered header `{name}`"),
            ));
        }
        if !expected.contains(&name.as_str()) {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                format!("unknown critical header `{name}`"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn reject_plugin(name: &str) -> Result<(), SignatureError> {
    if name == VERIFICATION_PLUGIN || name == VERIFICATION_PLUGIN_MIN_VERSION {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            format!("unsupported critical verification plugin header `{name}`"),
        ));
    }
    Ok(())
}

pub(crate) fn is_timestamp_header(name: &str) -> bool {
    name == TIMESTAMP_SIGNATURE || name == TIMESTAMP_ALIAS || name == "timestamp"
}

fn is_registered_header(name: &str) -> bool {
    matches!(
        name,
        "alg" | "cty" | "crit" | "jku" | "jwk" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "typ"
    )
}

pub(crate) fn finish_attributes(
    algorithm: Algorithm,
    scheme: SigningScheme,
    signing_time: Option<i64>,
    authentic_signing_time: Option<i64>,
    expiry: Option<i64>,
    content_type: &str,
    crit: &[String],
) -> Result<ParsedAttributes, SignatureError> {
    if content_type != PAYLOAD_MEDIA_TYPE {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "content type is not application/vnd.cncf.notary.payload.v1+json",
        ));
    }
    match scheme {
        SigningScheme::X509 => {
            if signing_time.is_none() {
                return Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "signingTime is required for notary.x509",
                ));
            }
            if authentic_signing_time.is_some() {
                return Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "authenticSigningTime is only valid for notary.x509.signingAuthority",
                ));
            }
        }
        SigningScheme::X509SigningAuthority => {
            if authentic_signing_time.is_none() {
                return Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "authenticSigningTime is required for notary.x509.signingAuthority",
                ));
            }
            if signing_time.is_some() {
                return Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "signingTime is only valid for notary.x509",
                ));
            }
        }
    }
    check_crit(crit, authentic_signing_time.is_some(), expiry.is_some())?;
    Ok(ParsedAttributes {
        algorithm,
        scheme,
        signing_time,
        authentic_signing_time,
        expiry,
    })
}
