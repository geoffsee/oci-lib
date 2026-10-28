# oci-util

Internal workspace support for `oci-lib`; this crate is not published on its own.

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

## Feature: `guest-embed`

Std-only guest attestation parse/check and the build-script helper
`vm::embed_guest`. Product `build.rs` files call it with an `EmbedConfig`
(env var names, `OUT_DIR` artifact names, protocol version).

## Feature: `vm`

macOS Virtualization host glue shared by `oci-builder`, `oci-runner`, and
`oci-cri`:

- entitlement self-sign (`ensure_entitlement`)
- virtiofs share planning (`Export`, `plan_shares`, `export_rootfs`)
- guest image materialize and VZ boot/vsock (`boot_vm`, `start_vm`,
  `connect_guest_vsock`, `GuestConfig`)

Product crates keep their own Go shims and wire protocols.
