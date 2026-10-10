// SPDX-License-Identifier: Apache-2.0

//! Diagnose lines for the guest attestation embedded next to the kernel.

#[path = "guest_attest.rs"]
mod attest;

// The build script compiles the checker on its own. Tests compile it here so
// the version gate and hash compare are exercised without booting a guest.
#[cfg(test)]
#[path = "guest_check.rs"]
mod check;

/// Kernel sha256, initramfs sha256, and each attested member path.
///
/// A document that does not parse becomes one `[fail]` line. Readiness stays
/// whatever the rest of diagnose already decided: the build refused a bad
/// attestation before these bytes were embedded.
pub(crate) fn lines_from_attestation(json: &str) -> Vec<String> {
    let attestation = match attest::parse(json) {
        Ok(attestation) => attestation,
        Err(err) => return vec![format!("[fail] embedded guest attestation: {err}")],
    };
    let mut lines = Vec::with_capacity(2 + attestation.members.len());
    lines.push(format!(
        "[ok] embedded guest kernel sha256 {}",
        attestation.kernel_sha256
    ));
    lines.push(format!(
        "[ok] embedded guest initramfs sha256 {}",
        attestation.initramfs_sha256
    ));
    for path in &attestation.members {
        lines.push(format!("[ok] initramfs member {path}"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnose_lists_hashes_then_member_paths_in_order() {
        let json = r#"{
            "package": "oci-builder",
            "kernel_sha256": "abc123",
            "initramfs_sha256": "def456",
            "members": [
                {"path": "bin", "mode": 16877, "size": 0, "sha256": "aa"},
                {"path": "bin/busybox", "mode": 33261, "size": 2, "sha256": "bb"}
            ]
        }"#;
        assert_eq!(
            lines_from_attestation(json),
            vec![
                "[ok] embedded guest kernel sha256 abc123".to_string(),
                "[ok] embedded guest initramfs sha256 def456".to_string(),
                "[ok] initramfs member bin".to_string(),
                "[ok] initramfs member bin/busybox".to_string(),
            ]
        );
    }

    #[test]
    fn an_empty_member_list_prints_only_the_hashes() {
        let json = r#"{"package":"oci-builder","kernel_sha256":"aa","initramfs_sha256":"bb","members":[]}"#;
        let lines = lines_from_attestation(json);
        assert_eq!(
            lines,
            vec![
                "[ok] embedded guest kernel sha256 aa".to_string(),
                "[ok] embedded guest initramfs sha256 bb".to_string(),
            ]
        );
    }

    #[test]
    fn a_bad_attestation_is_a_failed_line() {
        let lines = lines_from_attestation("not json");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("[fail] embedded guest attestation:"),
            "{lines:?}"
        );
    }
}
