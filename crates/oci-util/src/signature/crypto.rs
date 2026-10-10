//! RSA-PSS and ECDSA primitives for Notary envelopes and certificate chains.
//!
//! RSA uses `rsa` 0.9 (signature 2 / sha2 0.10). ECDSA uses the p256, p384, and
//! p521 stacks (signature 3). The traits are imported inside each function so the
//! two `signature` majors never meet in one scope.

use rsa::traits::PublicKeyParts;
use sha2::{Sha256, Sha384, Sha512};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{
    OID_EC_P256, OID_NIST_EC_P384, OID_NIST_EC_P521, OID_PKCS1_SHA256WITHRSA,
    OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA, OID_SIG_ECDSA_WITH_SHA256,
    OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ECDSA_WITH_SHA512,
};
use x509_parser::prelude::FromDer;

use super::error::{ErrorKind, SignatureError};

/// Notary signature algorithm. The leaf key selects exactly one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    Es512,
}

impl Algorithm {
    pub(crate) fn jws_name(self) -> &'static str {
        match self {
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
        }
    }

    pub(crate) fn cose_alg(self) -> i64 {
        match self {
            Self::Ps256 => -37,
            Self::Ps384 => -38,
            Self::Ps512 => -39,
            Self::Es256 => -7,
            Self::Es384 => -35,
            Self::Es512 => -36,
        }
    }

    pub(crate) fn from_jws(name: &str) -> Result<Self, SignatureError> {
        match name {
            "PS256" => Ok(Self::Ps256),
            "PS384" => Ok(Self::Ps384),
            "PS512" => Ok(Self::Ps512),
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            "ES512" => Ok(Self::Es512),
            other => Err(SignatureError::new(
                ErrorKind::Algorithm,
                format!("alg `{other}` is not a supported Notary signature algorithm"),
            )),
        }
    }

    pub(crate) fn from_cose(alg: i64) -> Result<Self, SignatureError> {
        match alg {
            -37 => Ok(Self::Ps256),
            -38 => Ok(Self::Ps384),
            -39 => Ok(Self::Ps512),
            -7 => Ok(Self::Es256),
            -35 => Ok(Self::Es384),
            -36 => Ok(Self::Es512),
            other => Err(SignatureError::new(
                ErrorKind::Algorithm,
                format!("alg {other} is not a supported Notary signature algorithm"),
            )),
        }
    }
}

pub(crate) enum PrivateKey {
    Rsa(rsa::RsaPrivateKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
}

pub(crate) enum PublicKey {
    Rsa(rsa::RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
}

impl PrivateKey {
    pub(crate) fn from_pkcs8(der: &[u8]) -> Result<Self, SignatureError> {
        {
            use rsa::pkcs8::DecodePrivateKey;
            if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
                return Ok(Self::Rsa(key));
            }
        }
        {
            use p256::pkcs8::DecodePrivateKey;
            if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(Self::P256(key));
            }
        }
        {
            use p384::pkcs8::DecodePrivateKey;
            if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(Self::P384(key));
            }
        }
        {
            use p521::pkcs8::DecodePrivateKey;
            if let Ok(key) = p521::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(Self::P521(key));
            }
        }
        Err(SignatureError::new(
            ErrorKind::Algorithm,
            "private key is not PKCS#8 RSA, P-256, P-384, or P-521",
        ))
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        match self {
            Self::Rsa(key) => PublicKey::Rsa(rsa::RsaPublicKey::from(key)),
            Self::P256(key) => PublicKey::P256(*key.verifying_key()),
            Self::P384(key) => PublicKey::P384(*key.verifying_key()),
            Self::P521(key) => PublicKey::P521(*key.verifying_key()),
        }
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
        match self {
            Self::Rsa(key) => match algorithm_for_rsa_bits(key.n().bits())? {
                Algorithm::Ps256 => rsa_sign_sha256(key, message),
                Algorithm::Ps384 => rsa_sign_sha384(key, message),
                Algorithm::Ps512 => rsa_sign_sha512(key, message),
                Algorithm::Es256 | Algorithm::Es384 | Algorithm::Es512 => Err(algorithm_mismatch()),
            },
            Self::P256(key) => ecdsa_sign_p256(key, message),
            Self::P384(key) => ecdsa_sign_p384(key, message),
            Self::P521(key) => ecdsa_sign_p521(key, message),
        }
    }
}

impl PublicKey {
    pub(crate) fn algorithm(&self) -> Result<Algorithm, SignatureError> {
        match self {
            Self::Rsa(key) => algorithm_for_rsa_bits(key.n().bits()),
            Self::P256(_) => Ok(Algorithm::Es256),
            Self::P384(_) => Ok(Algorithm::Es384),
            Self::P521(_) => Ok(Algorithm::Es512),
        }
    }

    pub(crate) fn matches(&self, other: &PublicKey) -> bool {
        match (self, other) {
            (Self::Rsa(left), Self::Rsa(right)) => left.n() == right.n() && left.e() == right.e(),
            (Self::P256(left), Self::P256(right)) => left.to_sec1_bytes() == right.to_sec1_bytes(),
            (Self::P384(left), Self::P384(right)) => left.to_sec1_bytes() == right.to_sec1_bytes(),
            (Self::P521(left), Self::P521(right)) => left.to_sec1_bytes() == right.to_sec1_bytes(),
            _ => false,
        }
    }

    pub(crate) fn verify(
        &self,
        algorithm: Algorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        let expected = self.algorithm()?;
        if algorithm != expected {
            return Err(SignatureError::new(
                ErrorKind::Algorithm,
                format!(
                    "alg {} does not match the leaf key ({})",
                    algorithm.jws_name(),
                    expected.jws_name()
                ),
            ));
        }
        match (self, algorithm) {
            (Self::Rsa(key), Algorithm::Ps256) => rsa_verify_sha256(key, message, signature),
            (Self::Rsa(key), Algorithm::Ps384) => rsa_verify_sha384(key, message, signature),
            (Self::Rsa(key), Algorithm::Ps512) => rsa_verify_sha512(key, message, signature),
            (Self::P256(key), Algorithm::Es256) => ecdsa_verify_p256(key, message, signature),
            (Self::P384(key), Algorithm::Es384) => ecdsa_verify_p384(key, message, signature),
            (Self::P521(key), Algorithm::Es512) => ecdsa_verify_p521(key, message, signature),
            _ => Err(algorithm_mismatch()),
        }
    }
}

pub(crate) fn public_key_from_cert(
    cert: &X509Certificate<'_>,
) -> Result<PublicKey, SignatureError> {
    let parsed = cert.public_key().parsed().map_err(|_| {
        SignatureError::new(
            ErrorKind::Certificate,
            "certificate public key could not be parsed",
        )
    })?;
    match parsed {
        x509_parser::public_key::PublicKey::RSA(key) => {
            let modulus = rsa::BigUint::from_bytes_be(key.modulus);
            let exponent = rsa::BigUint::from_bytes_be(key.exponent);
            let public = rsa::RsaPublicKey::new(modulus, exponent).map_err(|_| {
                SignatureError::new(ErrorKind::Certificate, "RSA public key is not valid")
            })?;
            Ok(PublicKey::Rsa(public))
        }
        x509_parser::public_key::PublicKey::EC(point) => {
            let curve = cert
                .public_key()
                .algorithm
                .parameters
                .as_ref()
                .and_then(|any| any.as_oid().ok())
                .ok_or_else(|| {
                    SignatureError::new(
                        ErrorKind::Certificate,
                        "EC certificate is missing a curve OID",
                    )
                })?;
            let data = point.data();
            if curve == OID_EC_P256 {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(data).map_err(|_| {
                    SignatureError::new(ErrorKind::Certificate, "P-256 public key is not valid")
                })?;
                Ok(PublicKey::P256(key))
            } else if curve == OID_NIST_EC_P384 {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(data).map_err(|_| {
                    SignatureError::new(ErrorKind::Certificate, "P-384 public key is not valid")
                })?;
                Ok(PublicKey::P384(key))
            } else if curve == OID_NIST_EC_P521 {
                let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(data).map_err(|_| {
                    SignatureError::new(ErrorKind::Certificate, "P-521 public key is not valid")
                })?;
                Ok(PublicKey::P521(key))
            } else {
                Err(SignatureError::new(
                    ErrorKind::Algorithm,
                    "EC certificate curve is not P-256, P-384, or P-521",
                ))
            }
        }
        _ => Err(SignatureError::new(
            ErrorKind::Algorithm,
            "certificate public key is not RSA or ECDSA",
        )),
    }
}

/// Reject SHA-1 certificate signatures before any cryptographic verification.
pub(crate) fn reject_sha1(cert: &X509Certificate<'_>) -> Result<(), SignatureError> {
    for oid in [
        &cert.signature_algorithm.algorithm,
        &cert.tbs_certificate.signature.algorithm,
    ] {
        let id = oid.to_id_string();
        if id == "1.2.840.113549.1.1.5" || id == "1.3.14.3.2.29" || id == "1.2.840.10045.4.1" {
            return Err(SignatureError::new(
                ErrorKind::Certificate,
                "certificate signature algorithm is SHA-1 and is rejected",
            ));
        }
    }
    Ok(())
}

pub(crate) fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, SignatureError> {
    let (rest, cert) = X509Certificate::from_der(der)
        .map_err(|_| SignatureError::new(ErrorKind::Certificate, "certificate is not DER X.509"))?;
    if !rest.is_empty() {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "certificate DER has trailing bytes",
        ));
    }
    Ok(cert)
}

/// Verify `cert` was signed by `issuer_key`. Certificate signatures are PKCS#1 v1.5 or DER ECDSA.
pub(crate) fn verify_cert_signature(
    cert: &X509Certificate<'_>,
    issuer_key: &PublicKey,
) -> Result<(), SignatureError> {
    reject_sha1(cert)?;
    let tbs = cert.tbs_certificate.as_ref();
    let signature = cert.signature_value.data.as_ref();
    if cert.signature_value.unused_bits != 0 {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature bit string is not byte-aligned",
        ));
    }
    let oid = &cert.signature_algorithm.algorithm;
    if *oid == OID_PKCS1_SHA256WITHRSA {
        pkcs1_verify_sha256(issuer_key, tbs, signature)
    } else if *oid == OID_PKCS1_SHA384WITHRSA {
        pkcs1_verify_sha384(issuer_key, tbs, signature)
    } else if *oid == OID_PKCS1_SHA512WITHRSA {
        pkcs1_verify_sha512(issuer_key, tbs, signature)
    } else if *oid == OID_SIG_ECDSA_WITH_SHA256 {
        ecdsa_cert_verify_p256(issuer_key, tbs, signature)
    } else if *oid == OID_SIG_ECDSA_WITH_SHA384 {
        ecdsa_cert_verify_p384(issuer_key, tbs, signature)
    } else if *oid == OID_SIG_ECDSA_WITH_SHA512 {
        ecdsa_cert_verify_p521(issuer_key, tbs, signature)
    } else {
        Err(SignatureError::new(
            ErrorKind::Algorithm,
            format!(
                "unsupported certificate signature algorithm {}",
                oid.to_id_string()
            ),
        ))
    }
}

fn algorithm_for_rsa_bits(bits: usize) -> Result<Algorithm, SignatureError> {
    match bits {
        2048 => Ok(Algorithm::Ps256),
        3072 => Ok(Algorithm::Ps384),
        4096 => Ok(Algorithm::Ps512),
        _ => Err(SignatureError::new(
            ErrorKind::Algorithm,
            format!("RSA key size {bits} is not 2048, 3072, or 4096"),
        )),
    }
}

fn algorithm_mismatch() -> SignatureError {
    SignatureError::new(ErrorKind::Algorithm, "alg does not match the leaf key")
}

fn signature_failed() -> SignatureError {
    SignatureError::new(ErrorKind::Signature, "signature verification failed")
}

fn rsa_issuer(key: &PublicKey) -> Result<&rsa::RsaPublicKey, SignatureError> {
    match key {
        PublicKey::Rsa(key) => Ok(key),
        _ => Err(SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature algorithm does not match the issuer key",
        )),
    }
}

fn rsa_sign_sha256(key: &rsa::RsaPrivateKey, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    let signer = rsa::pss::SigningKey::<Sha256>::new(key.clone());
    let mut rng = rsa::rand_core::OsRng;
    let signature = signer
        .try_sign_with_rng(&mut rng, message)
        .map_err(|_| SignatureError::new(ErrorKind::Signature, "RSA-PSS signing failed"))?;
    Ok(signature.to_vec())
}

fn rsa_sign_sha384(key: &rsa::RsaPrivateKey, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    let signer = rsa::pss::SigningKey::<Sha384>::new(key.clone());
    let mut rng = rsa::rand_core::OsRng;
    let signature = signer
        .try_sign_with_rng(&mut rng, message)
        .map_err(|_| SignatureError::new(ErrorKind::Signature, "RSA-PSS signing failed"))?;
    Ok(signature.to_vec())
}

fn rsa_sign_sha512(key: &rsa::RsaPrivateKey, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    let signer = rsa::pss::SigningKey::<Sha512>::new(key.clone());
    let mut rng = rsa::rand_core::OsRng;
    let signature = signer
        .try_sign_with_rng(&mut rng, message)
        .map_err(|_| SignatureError::new(ErrorKind::Signature, "RSA-PSS signing failed"))?;
    Ok(signature.to_vec())
}

fn rsa_verify_sha256(
    key: &rsa::RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    use rsa::signature::Verifier;
    let verifying = rsa::pss::VerifyingKey::<Sha256>::new(key.clone());
    let parsed = rsa::pss::Signature::try_from(signature).map_err(|_| signature_failed())?;
    verifying
        .verify(message, &parsed)
        .map_err(|_| signature_failed())
}

fn rsa_verify_sha384(
    key: &rsa::RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    use rsa::signature::Verifier;
    let verifying = rsa::pss::VerifyingKey::<Sha384>::new(key.clone());
    let parsed = rsa::pss::Signature::try_from(signature).map_err(|_| signature_failed())?;
    verifying
        .verify(message, &parsed)
        .map_err(|_| signature_failed())
}

fn rsa_verify_sha512(
    key: &rsa::RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    use rsa::signature::Verifier;
    let verifying = rsa::pss::VerifyingKey::<Sha512>::new(key.clone());
    let parsed = rsa::pss::Signature::try_from(signature).map_err(|_| signature_failed())?;
    verifying
        .verify(message, &parsed)
        .map_err(|_| signature_failed())
}

fn pkcs1_verify_sha256(
    issuer_key: &PublicKey,
    tbs: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    use rsa::signature::Verifier;
    let key = rsa_issuer(issuer_key)?;
    let verifying = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key.clone());
    let parsed = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| signature_failed())?;
    verifying.verify(tbs, &parsed).map_err(|_| {
        SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature verification failed",
        )
    })
}

fn pkcs1_verify_sha384(
    issuer_key: &PublicKey,
    tbs: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    use rsa::signature::Verifier;
    let key = rsa_issuer(issuer_key)?;
    let verifying = rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key.clone());
    let parsed = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| signature_failed())?;
    verifying.verify(tbs, &parsed).map_err(|_| {
        SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature verification failed",
        )
    })
}

fn pkcs1_verify_sha512(
    issuer_key: &PublicKey,
    tbs: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    use rsa::signature::Verifier;
    let key = rsa_issuer(issuer_key)?;
    let verifying = rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key.clone());
    let parsed = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| signature_failed())?;
    verifying.verify(tbs, &parsed).map_err(|_| {
        SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature verification failed",
        )
    })
}

fn ecdsa_cert_verify_p256(
    issuer_key: &PublicKey,
    tbs: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let PublicKey::P256(key) = issuer_key else {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature algorithm does not match the issuer key",
        ));
    };
    use p256::ecdsa::signature::Verifier;
    let parsed = p256::ecdsa::Signature::from_der(signature).map_err(|_| {
        SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature is not a valid ECDSA signature",
        )
    })?;
    key.verify(tbs, &parsed).map_err(|_| {
        SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature verification failed",
        )
    })
}

fn ecdsa_cert_verify_p384(
    issuer_key: &PublicKey,
    tbs: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let PublicKey::P384(key) = issuer_key else {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature algorithm does not match the issuer key",
        ));
    };
    use p384::ecdsa::signature::Verifier;
    let parsed = p384::ecdsa::Signature::from_der(signature).map_err(|_| {
        SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature is not a valid ECDSA signature",
        )
    })?;
    key.verify(tbs, &parsed).map_err(|_| {
        SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature verification failed",
        )
    })
}

fn ecdsa_cert_verify_p521(
    issuer_key: &PublicKey,
    tbs: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let PublicKey::P521(key) = issuer_key else {
        return Err(SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature algorithm does not match the issuer key",
        ));
    };
    use p521::ecdsa::signature::Verifier;
    let parsed = p521::ecdsa::Signature::from_der(signature).map_err(|_| {
        SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature is not a valid ECDSA signature",
        )
    })?;
    key.verify(tbs, &parsed).map_err(|_| {
        SignatureError::new(
            ErrorKind::Certificate,
            "certificate signature verification failed",
        )
    })
}

fn ecdsa_sign_p256(
    key: &p256::ecdsa::SigningKey,
    message: &[u8],
) -> Result<Vec<u8>, SignatureError> {
    use p256::ecdsa::signature::Signer;
    let signature: p256::ecdsa::Signature = key
        .try_sign(message)
        .map_err(|_| SignatureError::new(ErrorKind::Signature, "ECDSA signing failed"))?;
    Ok(signature.to_bytes().as_slice().to_vec())
}

fn ecdsa_sign_p384(
    key: &p384::ecdsa::SigningKey,
    message: &[u8],
) -> Result<Vec<u8>, SignatureError> {
    use p384::ecdsa::signature::Signer;
    let signature: p384::ecdsa::Signature = key
        .try_sign(message)
        .map_err(|_| SignatureError::new(ErrorKind::Signature, "ECDSA signing failed"))?;
    Ok(signature.to_bytes().as_slice().to_vec())
}

fn ecdsa_sign_p521(
    key: &p521::ecdsa::SigningKey,
    message: &[u8],
) -> Result<Vec<u8>, SignatureError> {
    use p521::ecdsa::signature::Signer;
    let signature: p521::ecdsa::Signature = key
        .try_sign(message)
        .map_err(|_| SignatureError::new(ErrorKind::Signature, "ECDSA signing failed"))?;
    Ok(signature.to_bytes().as_slice().to_vec())
}

fn ecdsa_verify_p256(
    key: &p256::ecdsa::VerifyingKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    use p256::ecdsa::signature::Verifier;
    let parsed = p256::ecdsa::Signature::from_slice(signature).map_err(|_| signature_failed())?;
    key.verify(message, &parsed).map_err(|_| signature_failed())
}

fn ecdsa_verify_p384(
    key: &p384::ecdsa::VerifyingKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    use p384::ecdsa::signature::Verifier;
    let parsed = p384::ecdsa::Signature::from_slice(signature).map_err(|_| signature_failed())?;
    key.verify(message, &parsed).map_err(|_| signature_failed())
}

fn ecdsa_verify_p521(
    key: &p521::ecdsa::VerifyingKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    use p521::ecdsa::signature::Verifier;
    let parsed = p521::ecdsa::Signature::from_slice(signature).map_err(|_| signature_failed())?;
    key.verify(message, &parsed).map_err(|_| signature_failed())
}
