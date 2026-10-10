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

---

## Build Requirements

- **Linux**: Go ≥ 1.26, C compiler (`gcc` or `clang`), `pkg-config`, and optionally `libseccomp-dev`.
- **macOS**: Built-in Apple Virtualization framework. Codesigning is automatically handled via `.cargo/config.toml` with the `com.apple.security.virtualization` entitlement.

---

## Limitations

- **Process Re-execution Hook**: On Linux, `startup()` must be the very first instruction in `main()`. If invoked after thread creation, async runtime initialization, or argument parsing, Buildah's rootless user namespace helpers and re-exec child dispatches will fail.
- **Rootless User Namespaces**: Building images rootless requires user namespaces (`/proc/sys/kernel/unprivileged_userns_clone = 1` or configured `/etc/subuid` and `/etc/subgid` ranges).
- **Isolation Dependencies**:
  - `chroot` isolation supports simple container builds (such as `FROM scratch` with `COPY`) without external helper binaries.
  - `oci` and `rootless` isolation require an OCI runtime binary (`runc` or `crun`) present on `$PATH` to execute `RUN` instructions.
  - Builds requiring network access during `RUN` instructions require network helper utilities (`netavark` or CNI).
- **macOS Guest Ephemeral Storage**: On macOS, builds execute inside a managed Linux Virtualization guest. Output artifacts (like pushed `docker-archive` tarballs) must target shared virtiofs mount directories to persist onto the macOS host.
- **Storage Driver in Nested Environments**: When running inside an existing Docker or container environment that lacks nested overlayfs kernel support, the `vfs` storage driver must be selected (`--storage-driver vfs`).
- **Platform Support**: Fully supported on Linux and macOS (the default `vm` feature embeds the Apple Virtualization guest). Other operating systems, and macOS with `vm` turned off, link a stub implementation that returns `ErrorCode::Unsupported`.
