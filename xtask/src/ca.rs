// SPDX-License-Identifier: Apache-2.0

//! Public trust roots for the Linux engines (including Go's crypto/x509).
//! Copy the build system's maintained CA bundle, never a generated root.

use std::path::Path;

use x509_parser::pem::Pem;

use super::Result;

pub(crate) const BUNDLE_PATH: &str = "etc/ssl/certs/ca-certificates.crt";

pub(crate) fn load(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).map_err(|err| {
        format!(
            "reading guest CA bundle {}: {err}; install ca-certificates on the Linux build system",
            path.display()
        )
    })?;
    validate(&bytes).map_err(|err| format!("guest CA bundle {}: {err}", path.display()))?;
    Ok(bytes)
}

fn validate(bytes: &[u8]) -> Result<()> {
    let mut certificates = 0;
    for pem in Pem::iter_from_buffer(bytes) {
        let pem = pem.map_err(|err| format!("invalid certificate PEM: {err}"))?;
        if pem.label != "CERTIFICATE" {
            return Err(format!("expected CERTIFICATE, found {}", pem.label));
        }
        let cert = pem
            .parse_x509()
            .map_err(|err| format!("invalid X.509 certificate: {err}"))?;
        if !cert.is_ca() {
            return Err("bundle contains a certificate that is not a CA".into());
        }
        certificates += 1;
    }
    if certificates == 0 {
        return Err(
            "no CA certificates found; install ca-certificates on the Linux build system".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_ca() -> Vec<u8> {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap()
        .pem()
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_bundle_of_ca_certificates() {
        let mut bundle = test_ca();
        bundle.extend(test_ca());
        validate(&bundle).unwrap();
    }

    #[test]
    fn rejects_empty_malformed_or_non_ca_bundles() {
        for bytes in [
            b"".as_slice(),
            b"not a certificate",
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ] {
            assert!(validate(bytes).is_err());
        }
        let leaf = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        assert!(
            validate(leaf.cert.pem().as_bytes())
                .unwrap_err()
                .contains("not a CA")
        );
        let mut mixed = test_ca();
        mixed.extend(leaf.key_pair.serialize_pem().bytes());
        assert!(validate(&mixed).unwrap_err().contains("PRIVATE KEY"));
        let mut truncated = test_ca();
        truncated.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        assert!(validate(&truncated).is_err());
    }
}
