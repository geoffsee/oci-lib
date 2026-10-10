//! Tagged COSE_Sign1 envelopes for Notary signatures.

use std::io::Cursor;

use ciborium::Value;
use ciborium::value::Integer;

use super::attributes::{self, ParsedAttributes, SIGNING_AGENT, SIGNING_SCHEME, SignedAttributes};
use super::error::{ErrorKind, SignatureError};
use super::payload::{PAYLOAD_MEDIA_TYPE, Payload};

const COSE_SIGN1_TAG: u64 = 18;
const LABEL_ALG: i64 = 1;
const LABEL_CRIT: i64 = 2;
const LABEL_CONTENT_TYPE: i64 = 3;
const LABEL_X5CHAIN: i64 = 33;

#[derive(Debug)]
pub(crate) struct CoseEnvelope {
    pub(crate) attributes: ParsedAttributes,
    pub(crate) payload: Vec<u8>,
    pub(crate) certificates: Vec<Vec<u8>>,
    pub(crate) signing_input: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) timestamp_present: bool,
}

pub(crate) struct PreparedCose {
    pub(crate) signing_input: Vec<u8>,
    protected: Vec<u8>,
    unprotected: Value,
    payload: Vec<u8>,
}

pub(crate) fn prepare(
    payload: &Payload,
    algorithm: i64,
    attributes: &SignedAttributes,
    certificate_chain: &[impl AsRef<[u8]>],
    signing_agent: Option<&str>,
) -> Result<PreparedCose, SignatureError> {
    attributes.validate()?;
    let protected_map = protected_map(algorithm, attributes)?;
    let mut protected = Vec::new();
    ciborium::ser::into_writer(&protected_map, &mut protected).map_err(|_| {
        SignatureError::new(
            ErrorKind::Encoding,
            "failed to encode COSE protected header",
        )
    })?;
    let payload_bytes = payload.to_bytes()?;
    let signing_input = sig_structure(&protected, &payload_bytes)?;
    Ok(PreparedCose {
        signing_input,
        protected,
        unprotected: unprotected_map(certificate_chain, signing_agent, None)?,
        payload: payload_bytes,
    })
}

pub(crate) fn finish(prepared: PreparedCose, signature: &[u8]) -> Result<Vec<u8>, SignatureError> {
    let cose = Value::Tag(
        COSE_SIGN1_TAG,
        Box::new(Value::Array(vec![
            Value::Bytes(prepared.protected),
            prepared.unprotected,
            Value::Bytes(prepared.payload),
            Value::Bytes(signature.to_vec()),
        ])),
    );
    let mut out = Vec::new();
    ciborium::ser::into_writer(&cose, &mut out)
        .map_err(|_| SignatureError::new(ErrorKind::Encoding, "failed to encode COSE_Sign1"))?;
    Ok(out)
}

pub(crate) fn parse(bytes: &[u8]) -> Result<CoseEnvelope, SignatureError> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|_| SignatureError::new(ErrorKind::Encoding, "COSE envelope is not CBOR"))?;
    if cursor.position() != u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "COSE envelope has trailing bytes",
        ));
    }
    let Value::Tag(COSE_SIGN1_TAG, inner) = value else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "COSE envelope is not a tagged COSE_Sign1",
        ));
    };
    let Value::Array(items) = *inner else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "COSE_Sign1 body is not an array",
        ));
    };
    if items.len() != 4 {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "COSE_Sign1 must contain protected, unprotected, payload, and signature",
        ));
    }
    let Value::Bytes(protected) = &items[0] else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "COSE protected header is not a byte string",
        ));
    };
    let Value::Map(unprotected) = &items[1] else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "COSE unprotected header is not a map",
        ));
    };
    let Value::Bytes(payload) = &items[2] else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "COSE payload is not a byte string",
        ));
    };
    let Value::Bytes(signature) = &items[3] else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "COSE signature is not a byte string",
        ));
    };
    let protected_map = decode_map(protected, "protected header")?;
    let attributes = parse_protected(&protected_map)?;
    let (certificates, timestamp_present) = parse_unprotected(unprotected, &protected_map)?;
    Ok(CoseEnvelope {
        attributes,
        payload: payload.clone(),
        certificates,
        signing_input: sig_structure(protected, payload)?,
        signature: signature.clone(),
        timestamp_present,
    })
}

fn sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, SignatureError> {
    let value = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).map_err(|_| {
        SignatureError::new(ErrorKind::Encoding, "failed to encode COSE Sig_structure")
    })?;
    Ok(out)
}

fn protected_map(algorithm: i64, attributes: &SignedAttributes) -> Result<Value, SignatureError> {
    let mut entries = vec![
        (int_key(LABEL_ALG), Value::Integer(Integer::from(algorithm))),
        (
            int_key(LABEL_CRIT),
            Value::Array(
                attributes::expected_crit(
                    attributes.authentic_signing_time.is_some(),
                    attributes.expiry.is_some(),
                )
                .into_iter()
                .map(|name| Value::Text(name.to_string()))
                .collect(),
            ),
        ),
        (
            int_key(LABEL_CONTENT_TYPE),
            Value::Text(PAYLOAD_MEDIA_TYPE.to_string()),
        ),
        (
            Value::Text(SIGNING_SCHEME.to_string()),
            Value::Text(attributes.scheme.as_str().to_string()),
        ),
    ];
    if let Some(time) = attributes.signing_time {
        entries.push((
            Value::Text(attributes::SIGNING_TIME.to_string()),
            epoch(time)?,
        ));
    }
    if let Some(time) = attributes.authentic_signing_time {
        entries.push((
            Value::Text(attributes::AUTHENTIC_SIGNING_TIME.to_string()),
            epoch(time)?,
        ));
    }
    if let Some(time) = attributes.expiry {
        entries.push((Value::Text(attributes::EXPIRY.to_string()), epoch(time)?));
    }
    Ok(Value::Map(entries))
}

fn unprotected_map(
    certificate_chain: &[impl AsRef<[u8]>],
    signing_agent: Option<&str>,
    timestamp: Option<&[u8]>,
) -> Result<Value, SignatureError> {
    if certificate_chain.is_empty() {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "certificate chain is empty",
        ));
    }
    let mut entries = vec![(
        int_key(LABEL_X5CHAIN),
        Value::Array(
            certificate_chain
                .iter()
                .map(|der| Value::Bytes(der.as_ref().to_vec()))
                .collect(),
        ),
    )];
    if let Some(agent) = signing_agent {
        entries.push((
            Value::Text(SIGNING_AGENT.to_string()),
            Value::Text(agent.to_string()),
        ));
    }
    if let Some(token) = timestamp {
        entries.push((
            Value::Text(attributes::TIMESTAMP_SIGNATURE.to_string()),
            Value::Bytes(token.to_vec()),
        ));
    }
    Ok(Value::Map(entries))
}

fn parse_protected(entries: &[(Value, Value)]) -> Result<ParsedAttributes, SignatureError> {
    reject_duplicate_keys(entries)?;
    for (key, _) in entries {
        if let Value::Text(name) = key {
            attributes::reject_plugin(name)?;
        }
    }
    let alg = map_i64(entries, LABEL_ALG).ok_or_else(|| {
        SignatureError::new(ErrorKind::Encoding, "COSE protected header is missing alg")
    })?;
    let algorithm = super::crypto::Algorithm::from_cose(alg)?;
    let content_type = map_text(entries, &int_key(LABEL_CONTENT_TYPE)).ok_or_else(|| {
        SignatureError::new(
            ErrorKind::Encoding,
            "COSE protected header is missing content type",
        )
    })?;
    let scheme = attributes::SigningScheme::parse(
        map_text(entries, &Value::Text(SIGNING_SCHEME.to_string())).ok_or_else(|| {
            SignatureError::new(
                ErrorKind::Encoding,
                "COSE protected header is missing signingScheme",
            )
        })?,
    )?;
    let signing_time = optional_epoch(entries, attributes::SIGNING_TIME)?;
    let authentic = optional_epoch(entries, attributes::AUTHENTIC_SIGNING_TIME)?;
    let expiry = optional_epoch(entries, attributes::EXPIRY)?;
    let crit_value = map_get(entries, &int_key(LABEL_CRIT)).ok_or_else(|| {
        SignatureError::new(ErrorKind::Encoding, "COSE protected header is missing crit")
    })?;
    let Value::Array(items) = crit_value else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "COSE crit is not an array",
        ));
    };
    let mut crit = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Text(text) => crit.push(text.clone()),
            Value::Integer(_) => {
                return Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "crit lists a registered COSE header label",
                ));
            }
            _ => {
                return Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "crit entries must be strings",
                ));
            }
        }
    }
    for (key, _) in entries {
        match key {
            Value::Integer(value) => {
                let label = i64::try_from(*value).map_err(|_| {
                    SignatureError::new(ErrorKind::Encoding, "COSE header label is out of range")
                })?;
                if label != LABEL_ALG && label != LABEL_CRIT && label != LABEL_CONTENT_TYPE {
                    return Err(SignatureError::new(
                        ErrorKind::Encoding,
                        format!("unknown COSE protected header label {label}"),
                    ));
                }
            }
            Value::Text(name) => {
                if name != SIGNING_SCHEME
                    && name != attributes::SIGNING_TIME
                    && name != attributes::AUTHENTIC_SIGNING_TIME
                    && name != attributes::EXPIRY
                {
                    return Err(SignatureError::new(
                        ErrorKind::Encoding,
                        format!("unknown protected header `{name}`"),
                    ));
                }
            }
            _ => {
                return Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "COSE protected header key has an unsupported type",
                ));
            }
        }
    }
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

fn parse_unprotected(
    entries: &[(Value, Value)],
    protected: &[(Value, Value)],
) -> Result<(Vec<Vec<u8>>, bool), SignatureError> {
    reject_duplicate_keys(entries)?;
    let mut certificates = certificates_from(entries)?;
    let protected_certs = certificates_from(protected)?;
    if certificates.is_some() && protected_certs.is_some() {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "x5chain is present in both COSE headers",
        ));
    }
    if certificates.is_none() {
        certificates = protected_certs;
    }
    let mut timestamp_present = false;
    for (key, value) in entries {
        match key {
            Value::Integer(label) => {
                let label = i64::try_from(*label).map_err(|_| {
                    SignatureError::new(ErrorKind::Encoding, "COSE header label is out of range")
                })?;
                if label != LABEL_X5CHAIN {
                    return Err(SignatureError::new(
                        ErrorKind::Encoding,
                        format!("unknown COSE unprotected header label {label}"),
                    ));
                }
            }
            Value::Text(name) => {
                attributes::reject_plugin(name)?;
                if name == SIGNING_AGENT {
                    if !matches!(value, Value::Text(text) if !text.is_empty()) {
                        return Err(SignatureError::new(
                            ErrorKind::Encoding,
                            "signingAgent must be a non-empty string",
                        ));
                    }
                } else if attributes::is_timestamp_header(name) {
                    timestamp_present = true;
                    if matches!(value, Value::Bytes(bytes) if bytes.is_empty())
                        || matches!(value, Value::Text(text) if text.is_empty())
                    {
                        return Err(SignatureError::new(
                            ErrorKind::Timestamp,
                            "RFC 3161 timestamp countersignature is present but empty",
                        ));
                    }
                } else {
                    return Err(SignatureError::new(
                        ErrorKind::Encoding,
                        format!("unknown COSE unprotected header `{name}`"),
                    ));
                }
            }
            _ => {
                return Err(SignatureError::new(
                    ErrorKind::Encoding,
                    "COSE unprotected header key has an unsupported type",
                ));
            }
        }
    }
    let certificates = certificates.ok_or_else(|| {
        SignatureError::new(ErrorKind::Encoding, "COSE header is missing x5chain")
    })?;
    Ok((certificates, timestamp_present))
}

fn certificates_from(entries: &[(Value, Value)]) -> Result<Option<Vec<Vec<u8>>>, SignatureError> {
    let Some(value) = map_get(entries, &int_key(LABEL_X5CHAIN)) else {
        return Ok(None);
    };
    let Value::Array(items) = value else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "x5chain is not an array of certificates",
        ));
    };
    if items.is_empty() {
        return Err(SignatureError::new(ErrorKind::Encoding, "x5chain is empty"));
    }
    let mut ders = Vec::with_capacity(items.len());
    for item in items {
        let Value::Bytes(bytes) = item else {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                "x5chain entries must be byte strings",
            ));
        };
        if bytes.is_empty() {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                "x5chain certificate is empty",
            ));
        }
        ders.push(bytes.clone());
    }
    Ok(Some(ders))
}

fn optional_epoch(entries: &[(Value, Value)], name: &str) -> Result<Option<i64>, SignatureError> {
    let Some(value) = map_get(entries, &Value::Text(name.to_string())) else {
        return Ok(None);
    };
    Ok(Some(read_epoch(value, name)?))
}

fn read_epoch(value: &Value, name: &str) -> Result<i64, SignatureError> {
    let Value::Tag(1, inner) = value else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            format!("{name} is not a COSE epoch date"),
        ));
    };
    let Value::Integer(integer) = inner.as_ref() else {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            format!("{name} uses fractional seconds"),
        ));
    };
    i64::try_from(*integer)
        .map_err(|_| SignatureError::new(ErrorKind::Encoding, format!("{name} is out of range")))
}

fn epoch(time: i64) -> Result<Value, SignatureError> {
    if time < 0 {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            "timestamp is before the Unix epoch",
        ));
    }
    Ok(Value::Tag(1, Box::new(Value::Integer(Integer::from(time)))))
}

fn decode_map(bytes: &[u8], name: &str) -> Result<Vec<(Value, Value)>, SignatureError> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor).map_err(|_| {
        SignatureError::new(ErrorKind::Encoding, format!("COSE {name} is not CBOR"))
    })?;
    if cursor.position() != u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(SignatureError::new(
            ErrorKind::Encoding,
            format!("COSE {name} has trailing bytes"),
        ));
    }
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(SignatureError::new(
            ErrorKind::Encoding,
            format!("COSE {name} is not a map"),
        )),
    }
}

fn map_get<'a>(entries: &'a [(Value, Value)], key: &Value) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value)
}

fn map_text<'a>(entries: &'a [(Value, Value)], key: &Value) -> Option<&'a str> {
    match map_get(entries, key) {
        Some(Value::Text(text)) => Some(text.as_str()),
        _ => None,
    }
}

fn map_i64(entries: &[(Value, Value)], label: i64) -> Option<i64> {
    match map_get(entries, &int_key(label)) {
        Some(Value::Integer(value)) => i64::try_from(*value).ok(),
        _ => None,
    }
}

fn int_key(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

fn reject_duplicate_keys(entries: &[(Value, Value)]) -> Result<(), SignatureError> {
    for (index, (key, _)) in entries.iter().enumerate() {
        if entries
            .iter()
            .skip(index + 1)
            .any(|(other, _)| other == key)
        {
            return Err(SignatureError::new(
                ErrorKind::Encoding,
                "COSE header repeats a key",
            ));
        }
    }
    Ok(())
}
