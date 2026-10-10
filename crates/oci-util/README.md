# oci-util

Shared Rust helpers for OCI tooling, independent of the builder and runner
engines. This is a library-only crate with no external dependencies or build
script.

The `signature` module is the home for signature helpers targeting the
[Notary Project v1.1.0 specification](https://github.com/notaryproject/specifications/blob/v1.1.0/specs/signature-specification.md).
The crate currently defines the module structure; signing, verification, trust
policy evaluation, and registry discovery are not implemented yet.
