// SPDX-License-Identifier: Apache-2.0

//! Hash and version checks for the guest attestation.
//!
//! `build.rs` compiles this file. The library compiles it only under test,
//! because diagnose never re-checks the hashes the build already verified.

use super::attest::Attestation;

pub(crate) fn version_requires_guest_attestation(version: &str) -> bool {
    compare_dotted_integers(version, "0.1.7") == std::cmp::Ordering::Greater
}

pub(crate) fn hashes_match(
    attestation: &Attestation,
    kernel_sha256: &str,
    initramfs_sha256: &str,
) -> Result<(), String> {
    // An empty path cannot be a cpio member. Reading the list here also keeps
    // the bill of materials attached to the document whose hashes we trust.
    if attestation.members.iter().any(|path| path.is_empty()) {
        return Err("attestation member path is empty".into());
    }
    if !attestation
        .kernel_sha256
        .eq_ignore_ascii_case(kernel_sha256)
    {
        return Err(format!(
            "kernel sha256 recorded {} does not match {kernel_sha256}",
            attestation.kernel_sha256
        ));
    }
    if !attestation
        .initramfs_sha256
        .eq_ignore_ascii_case(initramfs_sha256)
    {
        return Err(format!(
            "initramfs sha256 recorded {} does not match {initramfs_sha256}",
            attestation.initramfs_sha256
        ));
    }
    Ok(())
}

/// Check that the guest was built from the same package and wire protocol as
/// the host that is about to embed it.
pub(crate) fn compatibility_match(
    attestation: &Attestation,
    package: &str,
    package_version: &str,
    protocol_version: u32,
) -> Result<(), String> {
    if attestation.package != package {
        return Err(format!(
            "guest package {} does not match host package {package}",
            attestation.package
        ));
    }
    if attestation.package_version != package_version {
        return Err(format!(
            "guest package version {} does not match host version {package_version}",
            attestation.package_version
        ));
    }
    if attestation.protocol_version != protocol_version {
        return Err(format!(
            "guest protocol version {} does not match host protocol version {protocol_version}",
            attestation.protocol_version
        ));
    }
    if !attestation
        .members
        .iter()
        .any(|path| path == "etc/ssl/certs/ca-certificates.crt")
    {
        return Err("guest is missing the CA trust bundle etc/ssl/certs/ca-certificates.crt; rebuild with cargo xtask guest on Linux (with ca-certificates installed)".into());
    }
    Ok(())
}

/// Document written when the published release has no attestation asset.
///
/// Releases through 0.1.7 shipped `SHA256SUMS` only. The member list is empty
/// because those bytes were not recorded.
#[cfg(test)]
pub(crate) fn minimal_attestation(
    package: &str,
    package_version: &str,
    protocol_version: u32,
    kernel_sha256: &str,
    initramfs_sha256: &str,
) -> String {
    format!(
        "{{\n  \"package\": {package},\n  \"package_version\": {package_version},\n  \"protocol_version\": {protocol_version},\n  \"kernel_sha256\": {kernel},\n  \"initramfs_sha256\": {initramfs},\n  \"members\": []\n}}\n",
        package = json_string(package),
        package_version = json_string(package_version),
        protocol_version = protocol_version,
        kernel = json_string(kernel_sha256),
        initramfs = json_string(initramfs_sha256),
    )
}

#[cfg(test)]
fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Component-wise integer compare. `"0.1.10"` is newer than `"0.1.7"`;
/// a string compare would order them the other way.
fn compare_dotted_integers(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left = dotted_integers(left);
    let mut right = dotted_integers(right);
    let width = left.len().max(right.len());
    left.resize(width, 0);
    right.resize(width, 0);
    left.cmp(&right)
}

fn dotted_integers(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|part| {
            let end = part
                .find(|ch: char| !ch.is_ascii_digit())
                .unwrap_or(part.len());
            part[..end].parse::<u64>().unwrap_or(0)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::attest::parse;
    use super::*;

    #[test]
    fn attestation_is_required_only_after_0_1_7() {
        assert!(!version_requires_guest_attestation("0.1.7"));
        assert!(!version_requires_guest_attestation("0.1.6"));
        assert!(!version_requires_guest_attestation("0.1"));
        assert!(!version_requires_guest_attestation("0.0.9"));
        assert!(!version_requires_guest_attestation("0.1.7.0"));
        assert!(version_requires_guest_attestation("0.1.8"));
        // Lexical order would treat this as older than 0.1.7.
        assert!(version_requires_guest_attestation("0.1.10"));
        assert!(version_requires_guest_attestation("0.2.0"));
        assert!(version_requires_guest_attestation("1.0.0"));
    }

    #[test]
    fn hashes_must_match_the_files_case_insensitively() {
        let json = minimal_attestation("oci-builder", "0.1.9", 2, "AbC", "def");
        let attestation = parse(&json).unwrap();
        assert!(attestation.members.is_empty());
        assert_eq!(attestation.package, "oci-builder");
        assert_eq!(attestation.package_version, "0.1.9");
        assert_eq!(attestation.protocol_version, 2);
        hashes_match(&attestation, "abc", "DEF").unwrap();
        let kernel = hashes_match(&attestation, "nope", "def").unwrap_err();
        assert!(kernel.contains("kernel sha256"), "{kernel}");
        let initramfs = hashes_match(&attestation, "abc", "nope").unwrap_err();
        assert!(initramfs.contains("initramfs sha256"), "{initramfs}");
    }

    #[test]
    fn an_empty_member_path_is_rejected() {
        let attestation = Attestation {
            package: "oci-builder".into(),
            package_version: "0.1.9".into(),
            protocol_version: 2,
            kernel_sha256: "abc".into(),
            initramfs_sha256: "def".into(),
            members: vec!["".into()],
        };
        let err = hashes_match(&attestation, "abc", "def").unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn compatibility_rejects_a_different_protocol() {
        let json = minimal_attestation("oci-builder", "0.1.9", 1, "abc", "def");
        let attestation = parse(&json).unwrap();
        let err = compatibility_match(&attestation, "oci-builder", "0.1.9", 2).unwrap_err();
        assert!(err.contains("protocol version"), "{err}");
    }

    #[test]
    fn compatibility_requires_ca_bundle_even_when_hashes_and_versions_match() {
        let json = minimal_attestation("oci-builder", "0.1.9", 2, "abc", "def");
        let mut attestation = parse(&json).unwrap();
        hashes_match(&attestation, "abc", "def").unwrap();
        let err = compatibility_match(&attestation, "oci-builder", "0.1.9", 2).unwrap_err();
        assert!(err.contains("CA trust bundle"), "{err}");
        attestation
            .members
            .push("etc/ssl/certs/ca-certificates.crt".into());
        compatibility_match(&attestation, "oci-builder", "0.1.9", 2).unwrap();
    }
}
