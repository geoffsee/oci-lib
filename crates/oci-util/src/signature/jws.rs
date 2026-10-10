//! Flattened JWS JSON serialization for Notary signatures.

use serde::Serialize;
use serde_json::{Map, Value};

use super::attributes::{self, ParsedAttributes, SIGNING_AGENT, SIGNING_SCHEME, SignedAttributes};
use super::b64::{b64_decode, b64_encode, b64url_decode, b64url_encode};
use super::error::{ErrorKind, SignatureError};
use super::payload::{PAYLOAD_MEDIA_TYPE, Payload};
use super::timeutil;

#[derive(Debug)]
pub(crate) struct JwsEnvelope {
    pub(crate) attributes: ParsedAttributes,
    pub(crate) payload: Vec<u8>,
    pub(crate) certificates: Vec<Vec<u8>>,
    pub(crate) signing_input: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) timestamp_present: bool,
}

#[derive(Serialize)]
struct ProtectedHeader<'a> {
    alg: &'a str,
    cty: &'a str,
    #[serde(rename = "io.cncf.notary.signingScheme")]
    scheme: &'a str,
    #[serde(
        rename = "io.cncf.notary.signingTime",
        skip_serializing_if = "Option::is_none"
    )]
    signing_time: Option<String>,
    #[serde(
        rename = "io.cncf.notary.authenticSigningTime",
        skip_serializing_if = "Option::is_none"
    )]
    authentic_signing_time: Option<String>,
    #[serde(
        rename = "io.cncf.notary.expiry",
        skip_serializing_if = "Option::is_none"
    )]
    expiry: Option<String>,
    crit: Vec<&'a str>,
}

pub(crate) struct PreparedJws {
    pub(crate) signing_input: Vec<u8>,
    payload_b64: String,
    protected_b64: String,
    header: Map<String, Value>,
}

pub(crate) fn prepare(
    payload: &Payload,
    algorithm_name: &str,
    attributes: &SignedAttributes,
    certificate_chain: &[impl AsRef<[u8]>],
    signing_agent: Option<&str>,
) -> Result<PreparedJws, SignatureError> {
    attributes.validate()?;
    let protected = ProtectedHeader {
        alg: algorithm_name,
        cty: PAYLOAD_MEDIA_TYPE,
        scheme: attributes.scheme.as_str(),
        signing_time: match attributes.signing_time {
            Some(time) => Some(timeutil::format_rfc3339(time)?),
            None => None,
        },
        authentic_signing_time: match attributes.authentic_signing_time {
            Some(time) => Some(timeutil::format_rfc3339(time)?),
            None => None,
        },
        expiry: match attributes.expiry {
            Some(time) => Some(timeutil::format_rfc3339(time)?),
            None => None,
        },
        crit: attributes::expected_crit(
            attributes.authentic_signing_time.is_some(),
            attributes.expiry.is_some(),
        ),
    };
    let protected_json = serde_json::to_vec(&protected).map_err(|err| {
        SignatureError::new(
            ErrorKind::Encoding,
            format!("failed to encode JWS header: {err}"),
        )
    })?;
    let payload_bytes = payload.to_bytes()?;
    let protected_b64 = b64url_encode(&protected_json);
    let payload_b64 = b64url_encode(&payload_bytes);
    let mut header = Map::new();
    let x5c: Vec<Value> = certificate_chain
        .iter()
        .map(|der| Value::String(b64_encode(der.as_ref())))
        .collect();
    header.insert("x5c".to_string(), Value::Array(x5c));
    if let Some(agent) = signing_agent {
        header.insert(SIGNING_AGENT.to_string(), Value::String(agent.to_string()));
    }
    Ok(PreparedJws {
        signing_input: signing_input(&protected_b64, &payload_b64),
        payload_b64,
        protected_b64,
        header,
    })
}

pub(crate) fn finish(prepared: PreparedJws, signature: &[u8]) -> Result<Vec<u8>, SignatureError> {
    let document = serde_json::json!({
        "payload": prepared.payload_b64,
        "protected": prepared.protected_b64,
        "header": prepared.header,
        "signature": b64url_encode(signature),
    });
    serde_json::to_vec(&document).map_err(|err| {
        SignatureError::new(ErrorKind::Encoding, format!("failed to encode JWS: {err}"))
    })
}

pub(crate) fn signing_input(protected_b64: &str, payload_b64: &str) -> Vec<u8> {
    let mut input = Vec::with_capacity(protected_b64.len() + 1 + payload_b64.len());
    input.extend(protected_b64.as_bytes());
    input.push(b'.');
    input.extend(payload_b64.as_bytes());
    input
}

pub(crate) fn parse(bytes: &[u8]) -> Result<JwsEnvelope, SignatureError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| {
        SignatureError::new(ErrorKind::Encoding, "JWS envelope is not flattened JSON")
    })?;
    let Value::Object(document) = value else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "JWS envelope is not a JSON object",
        ));
    };
    let allowed = ["payload", "protected", "header", "signature"];
    if document.len() != allowed.len() || allowed.iter().any(|key| !document.contains_key(*key)) {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "JWS envelope must contain only payload, protected, header, and signature",
        ));
    }
    let payload_b64 = expect_string(document.get("payload"), "payload")?;
    let protected_b64 = expect_string(document.get("protected"), "protected")?;
    let signature_b64 = expect_string(document.get("signature"), "signature")?;
    let header = match document.get("header") {
        Some(Value::Object(header)) => header,
        _ => {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                "JWS unprotected header is missing",
            ));
        }
    };
    let protected_json = b64url_decode(protected_b64)?;
    let protected: Value = serde_json::from_slice(&protected_json).map_err(|_| {
        SignatureError::new(ErrorKind::Encoding, "JWS protected header is not JSON")
    })?;
    let Value::Object(protected) = protected else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "JWS protected header is not a JSON object",
        ));
    };
    let attributes = parse_protected(&protected)?;
    let (certificates, timestamp_present) = parse_unprotected(header)?;
    let payload = b64url_decode(payload_b64)?;
    let signature = b64url_decode(signature_b64)?;
    Ok(JwsEnvelope {
        attributes,
        payload,
        certificates,
        signing_input: signing_input(protected_b64, payload_b64),
        signature,
        timestamp_present,
    })
}

fn parse_protected(header: &Map<String, Value>) -> Result<ParsedAttributes, SignatureError> {
    for key in header.keys() {
        attributes::reject_plugin(key)?;
    }
    let known = [
        "alg",
        "cty",
        "crit",
        SIGNING_SCHEME,
        attributes::SIGNING_TIME,
        attributes::AUTHENTIC_SIGNING_TIME,
        attributes::EXPIRY,
    ];
    for key in header.keys() {
        if !known.contains(&key.as_str()) {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                format!("unknown protected header `{key}`"),
            ));
        }
    }
    let alg = expect_string(header.get("alg"), "alg")?;
    let algorithm = super::crypto::Algorithm::from_jws(alg)?;
    let content_type = expect_string(header.get("cty"), "cty")?;
    let scheme = attributes::SigningScheme::parse(expect_string(
        header.get(SIGNING_SCHEME),
        SIGNING_SCHEME,
    )?)?;
    let signing_time = optional_time(header, attributes::SIGNING_TIME)?;
    let authentic = optional_time(header, attributes::AUTHENTIC_SIGNING_TIME)?;
    let expiry = optional_time(header, attributes::EXPIRY)?;
    let crit = match header.get("crit") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.clone()),
                _ => Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "crit entries must be strings",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                "crit is required in the JWS protected header",
            ));
        }
    };
    attributes::finish_attributes(
        algorithm,
        scheme,
        signing_time,
        authentic,
        expiry,
        content_type,
        &crit,
    )
}

fn parse_unprotected(header: &Map<String, Value>) -> Result<(Vec<Vec<u8>>, bool), SignatureError> {
    let mut timestamp_present = false;
    let mut certificates = None;
    for (key, value) in header {
        attributes::reject_plugin(key)?;
        if key == "x5c" {
            let Value::Array(items) = value else {
                return Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "x5c is not an array",
                ));
            };
            if items.is_empty() {
                return Err(SignatureError::new(ErrorKind::Encoding, "x5c is empty"));
            }
            let mut ders = Vec::with_capacity(items.len());
            for item in items {
                let Value::String(text) = item else {
                    return Err(SignatureError::new(
                        ErrorKind::Encoding,
                        "x5c entries must be strings",
                    ));
                };
                ders.push(b64_decode(text)?);
            }
            certificates = Some(ders);
        } else if key == SIGNING_AGENT {
            if !matches!(value, Value::String(text) if !text.is_empty()) {
                return Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "signingAgent must be a non-empty string",
                ));
            }
        } else if attributes::is_timestamp_header(key) {
            timestamp_present = timestamp_value_present(value)?;
        } else {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                format!("unknown JWS unprotected header `{key}`"),
            ));
        }
    }
    let certificates = certificates.ok_or_else(|| {
        SignatureError::new(ErrorKind::Encoding, "JWS unprotected header is missing x5c")
    })?;
    Ok((certificates, timestamp_present))
}

fn timestamp_value_present(value: &Value) -> Result<bool, SignatureError> {
    match value {
        Value::String(text) if text.is_empty() => Err(SignatureError::new(
            ErrorKind::Timestamp,
            "RFC 3161 timestamp countersignature is present but empty",
        )),
        Value::String(_) | Value::Array(_) | Value::Object(_) => Ok(true),
        Value::Null => Ok(false),
        _ => Err(SignatureError::new(
            ErrorKind::Timestamp,
            "RFC 3161 timestamp countersignature is present but has an unsupported shape",
        )),
    }
}

fn optional_time(header: &Map<String, Value>, name: &str) -> Result<Option<i64>, SignatureError> {
    match header.get(name) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(timeutil::parse_rfc3339(text)?)),
        Some(_) => Err(SignatureError::new(
            ErrorKind::Encoding,
            format!("{name} is not an RFC 3339 string"),
        )),
    }
}

fn expect_string<'a>(value: Option<&'a Value>, name: &str) -> Result<&'a str, SignatureError> {
    match value {
        Some(Value::String(text)) if !text.is_empty() => Ok(text),
        _ => Err(SignatureError::new(
            ErrorKind::Encoding,
            format!("JWS field `{name}` is missing"),
        )),
    }
}
