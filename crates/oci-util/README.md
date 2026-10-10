# oci-util

Shared Rust helpers for OCI tooling, independent of the builder and runner
engines. This is a library-only crate. It depends on serde and the signature
crates it needs for Notary envelopes. It does not speak HTTP, and it does not
depend on Buildah or Podman.

The `signature` module implements the
[Notary Project v1.1.0 signature specification](https://github.com/notaryproject/specifications/blob/v1.1.0/specs/signature-specification.md):
payloads, signature manifests, JWS and COSE envelopes, certificate and
algorithm checks, trust-policy evaluation, and OCI referrers selection.

The caller downloads registry bytes and supplies trust anchors. A timestamp
countersignature fails closed: this crate does not verify RFC 3161 tokens.
