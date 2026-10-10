//! Produce a Notary JWS envelope, COSE envelope, or signature manifest.

use super::attributes::SignedAttributes;
use super::cert;
use super::cose;
use super::crypto::PrivateKey;
use super::error::SignatureError;
use super::jws;
use super::payload::Payload;

/// Sign `payload` and return a flattened JWS JSON envelope.
pub fn sign_jws(
    payload: &Payload,
    private_key_pkcs8: &[u8],
    certificate_chain: &[impl AsRef<[u8]>],
    attributes: &SignedAttributes,
    signing_agent: Option<&str>,
) -> Result<Vec<u8>, SignatureError> {
    let key = PrivateKey::from_pkcs8(private_key_pkcs8)?;
    let at = attributes.certificate_time()?;
    cert::check_chain_for_signing(certificate_chain, at, &key.public_key())?;
    let prepared = jws::prepare(
        payload,
        key.public_key().algorithm()?.jws_name(),
        attributes,
        certificate_chain,
        signing_agent,
    )?;
    let signature = key.sign(&prepared.signing_input)?;
    jws::finish(prepared, &signature)
}

/// Sign `payload` and return a tagged COSE_Sign1 envelope.
pub fn sign_cose(
    payload: &Payload,
    private_key_pkcs8: &[u8],
    certificate_chain: &[impl AsRef<[u8]>],
    attributes: &SignedAttributes,
    signing_agent: Option<&str>,
) -> Result<Vec<u8>, SignatureError> {
    let key = PrivateKey::from_pkcs8(private_key_pkcs8)?;
    let at = attributes.certificate_time()?;
    cert::check_chain_for_signing(certificate_chain, at, &key.public_key())?;
    let algorithm = key.public_key().algorithm()?.cose_alg();
    let prepared = cose::prepare(
        payload,
        algorithm,
        attributes,
        certificate_chain,
        signing_agent,
    )?;
    let signature = key.sign(&prepared.signing_input)?;
    cose::finish(prepared, &signature)
}
