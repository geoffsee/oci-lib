// SPDX-License-Identifier: Apache-2.0

//! Kubernetes image defaults, shared by pulls and local image lookups.

use oci_spec::distribution::Reference;

use crate::{Error, ErrorCode};

pub(crate) fn normalize(requested: &str) -> crate::error::Result<String> {
    // Local image IDs are opaque identities, not repositories on Docker Hub.
    let id = requested.strip_prefix("sha256:").unwrap_or(requested);
    if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(requested.to_string());
    }
    let reference: Reference = requested.parse().map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            "invalid image reference",
            format!("{error}"),
        )
    })?;
    // A digest takes precedence over a tag. The stored RepoDigest has no tag.
    Ok(match reference.digest() {
        Some(digest) => reference.clone_with_digest(digest.to_string()).whole(),
        None => reference.whole(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_names_use_kubernetes_defaults() {
        for (input, expected) in [
            ("busybox", "docker.io/library/busybox:latest"),
            ("busybox:1.36", "docker.io/library/busybox:1.36"),
            ("library/busybox:1.36", "docker.io/library/busybox:1.36"),
            ("docker.io/busybox:1.36", "docker.io/library/busybox:1.36"),
            (
                "index.docker.io/busybox",
                "docker.io/library/busybox:latest",
            ),
            ("team/app:v1", "docker.io/team/app:v1"),
            (
                "registry.example/team/app:v1",
                "registry.example/team/app:v1",
            ),
            ("localhost:5000/app", "localhost:5000/app:latest"),
            ("registry:5000/app:v1", "registry:5000/app:v1"),
        ] {
            assert_eq!(normalize(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn digests_override_tags_and_ids_are_not_repository_names() {
        let hash = "a".repeat(64);
        let digest = format!("sha256:{hash}");
        for name in [
            format!("busybox@{digest}"),
            format!("busybox:1.36@{digest}"),
        ] {
            assert_eq!(
                normalize(&name).unwrap(),
                format!("docker.io/library/busybox@{digest}")
            );
        }
        for id in [hash, digest] {
            assert_eq!(normalize(&id).unwrap(), id);
        }
    }

    #[test]
    fn invalid_names_are_rejected() {
        for name in ["", "bad image", "busybox@sha256:abc"] {
            assert!(normalize(name).is_err(), "{name}");
        }
    }
}
