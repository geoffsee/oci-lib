# oci-builder

[![Crates.io](https://img.shields.io/crates/v/oci-builder.svg)](https://crates.io/crates/oci-builder)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

Rust library (`oci_builder`) and CLI (`oci-builder`) that embeds [Buildah](https://github.com/containers/buildah) directly in-process. There is no Buildah daemon and no `buildah` executable on `$PATH`.

- **Linux**: Runs the Buildah engine directly in-process via a statically linked Go C-archive (`-buildmode=c-archive`) with priority 101 user namespace setup.
- **macOS** (default `vm` feature): Runs the engine inside a lightweight Linux guest managed by Apple's Virtualization framework over virtio-vsock.
- **Other OSes**: Links a lightweight stub returning `ErrorCode::Unsupported`.

---

## Installation

### Add as a Library Dependency

```toml
[dependencies]
oci-builder = "0.1"
```

### Install CLI Binary

```bash
cargo install oci-builder
```

---

## Rust Library Usage

> [!IMPORTANT]
> On Linux, `startup()` **must** be called at the very beginning of `main()`, before spawning threads or parsing CLI arguments. Buildah re-executes `/proc/self/exe` for rootless user namespaces and helper child processes.

```rust
use oci_builder::{startup, BuildRequest, Builder, Config, StorageDriver};

fn main() -> Result<(), oci_builder::Error> {
    // 1. Mandatory re-exec dispatch
    startup()?;

    // 2. Open builder instance
    let builder = Builder::open(Config {
        storage_driver: Some(StorageDriver::Vfs),
        ..Config::default()
    })?;

    // 3. Build an OCI container image
    let info = builder.build(
        BuildRequest::new("Dockerfile", ".")
            .with_tag("localhost/app:latest")
            .with_log(|record| {
                eprint!("{}", record.message);
            }),
    )?;

    println!("Successfully built image ID: {}", info.image_id);

    // 4. Clean up mounts & storage
    builder.shutdown()?;
    Ok(())
}
```

---

## CLI Usage

### Check System Prerequisites
```bash
oci-builder diagnose
```

### Build an Image
```bash
oci-builder --root /tmp/graph --runroot /tmp/run --storage-driver vfs \
  --signature-policy policy.json \
  build -f Dockerfile -t localhost/app:latest --pull never --isolation chroot
```

### Push an Image
```bash
oci-builder --root /tmp/graph --runroot /tmp/run --storage-driver vfs \
  --signature-policy policy.json \
  push localhost/app:latest localhost:5000/app:latest --insecure
```

`policy.json` for a local store without remote signature checks:
```json
{"default":[{"type":"insecureAcceptAnything"}]}
```

Passing `--signature-policy` is optional when the `default-policy` feature is on (it is part of the default features). An unset policy then uses the containers-common rules below, not a global `insecureAcceptAnything`.

---

## Signature policy

`default-policy` is a default feature. When `Config.signature_policy` is `None`, the library writes an embedded policy to a temporary file and passes that path to containers/image:

- `default` is `reject`
- `docker` transport, hostname `localhost`: `insecureAcceptAnything`
- `docker-daemon` transport, empty host: `insecureAcceptAnything`

A path you set is used as-is, and the embedded policy is not. Without the feature, `None` leaves discovery to containers/image, which fails closed when no policy file exists. On macOS, turn the feature off with `--no-default-features --features vm`. On Linux, `--no-default-features` is enough.

---

## Ignore files and excludes

`BuildRequest.excludes` adds dockerignore patterns. Empty means no extra patterns. The ignore file is chosen the way Buildah v1.45.1 `parse.ContainerIgnoreFile` chooses it:

- A Dockerfile-specific ignore beside the Dockerfile is chosen before context-root files.
- If both `<Dockerfile>.containerignore` and `<Dockerfile>.dockerignore` exist, `.dockerignore` wins.
- Otherwise the context-root `.containerignore` is used when present, else the context-root `.dockerignore`. The two root files are not merged.
- `excludes` are appended after that file. They do not replace it.

Syntax is Docker's dockerignore. Blank lines and `#` comments are ignored, `!` negates, the last match wins, and `**` matches across directories. A pattern `.env*` does not exclude `nested/.env.synthetic`. Pass `**/.env*` (or the same pattern in `excludes`) to match that name in every directory.

On macOS the build context exported to the guest is a filtered copy of that directory. Excluded paths are not on the virtiofs share. The Dockerfile is always staged, even if a pattern names it. Ignore files may be omitted from the guest. That share is read-only. The storage-root share stays writable, because the guest writes its graph there. On Linux there is no guest share; the same patterns are still passed to Buildah so `COPY` and `ADD` honor them.

On macOS, `Isolation::Default` (the CLI default) is sent as `chroot`. `Isolation::Oci` and `Isolation::Rootless` fail before the VM starts: this guest has no OCI runtime, and `chroot` is the supported isolation. Linux isolation is unchanged.

---

## Build Requirements

- **Linux**: Go ≥ 1.26, C compiler (`gcc` or `clang`), `pkg-config`, and optionally `libseccomp-dev`.
- **macOS**: Built-in Apple Virtualization framework. `startup()` signs the binary with the embedded `com.apple.security.virtualization` entitlement when it is missing, then re-executes it.

---

## Limitations

- **Process Re-execution Hook**: On Linux, `startup()` must be the very first instruction in `main()`. If invoked after thread creation, async runtime initialization, or argument parsing, Buildah's rootless user namespace helpers and re-exec child dispatches will fail.
- **Rootless User Namespaces**: Building images rootless requires user namespaces (`/proc/sys/kernel/unprivileged_userns_clone = 1` or configured `/etc/subuid` and `/etc/subgid` ranges).
- **Isolation Dependencies**:
  - `chroot` isolation supports simple container builds (such as `FROM scratch` with `COPY`) without external helper binaries.
  - `oci` and `rootless` isolation require an OCI runtime binary (`runc` or `crun`) present on `$PATH` to execute `RUN` instructions. The macOS guest has neither, so those modes fail before the VM starts and the default is `chroot`.
  - Builds requiring network access during `RUN` instructions require network helper utilities (`netavark` or CNI).
- **macOS Guest Ephemeral Storage**: On macOS, builds execute inside a managed Linux Virtualization guest. Output artifacts (like pushed `docker-archive` tarballs) must target shared virtiofs mount directories to persist onto the macOS host.
- **Storage Driver in Nested Environments**: When running inside an existing Docker or container environment that lacks nested overlayfs kernel support, the `vfs` storage driver must be selected (`--storage-driver vfs`).
- **Platform Support**: Fully supported on Linux and macOS (the default `vm` feature embeds the Apple Virtualization guest). Other operating systems, and macOS with `vm` turned off, link a stub implementation that returns `ErrorCode::Unsupported`.
