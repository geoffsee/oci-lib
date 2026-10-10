# oci-lib

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![oci-builder on crates.io](https://img.shields.io/crates/v/oci-builder.svg?label=oci-builder)](https://crates.io/crates/oci-builder)
[![oci-runner on crates.io](https://img.shields.io/crates/v/oci-runner.svg?label=oci-runner)](https://crates.io/crates/oci-runner)

A Rust monorepo for daemonless OCI image building and container execution.

`oci-lib` provides pure in-process libraries and standalone CLIs for building OCI images and running containers without requiring external daemons (`dockerd`, `containerd`, `podman`) or external runtime binaries (`buildah`, `runc`, `crun`) on `$PATH`.

---

## Crates Overview

| Crate | Binary | Engine | Capability | Linux Architecture | macOS Architecture |
|---|---|---|---|---|---|
| [`oci-builder`](crates/oci-builder) | `oci-builder` | [Buildah](https://github.com/containers/buildah) | Build & push OCI container images | In-process Go c-archive (`startup()`) | Apple Virtualization Linux guest (vsock) |
| [`oci-runner`](crates/oci-runner) | `oci-runner` | [libcontainer](https://github.com/opencontainers/runc/tree/main/libcontainer) | Execute foreground containers from a rootfs | In-process Go c-archive (`startup()`) | Apple Virtualization Linux guest (vsock) |

[`oci-util`](crates/oci-util) provides the shared utility library, including the
module structure for Notary Project signature helpers.

The builder and runner share a unified architectural pattern:
- **Zero Daemons**: Everything executes synchronously in-process.
- **Linux**: Statically links Go c-archives with early constructors (priority 101) to handle Linux user and mount namespaces without separate helper executables.
- **macOS** (default `vm` feature): Transparently manages a tiny Apple Virtualization Linux guest communicating via length-prefixed virtio-vsock frames over port 5253. The guest kernel and initramfs are zstd-compressed into the binary.
- **Self-Contained**: Can be embedded directly into orchestrators, test harnesses, or Kubernetes node runtimes (such as `rubix-kube`).

---

## Installation

### Add to `Cargo.toml`

```toml
[dependencies]
# For image building:
oci-builder = "0.1"

# For container execution:
oci-runner = "0.1"
```

On macOS, the default `vm` feature runs the engine in an Apple Virtualization Linux guest embedded in the binary. Its dependencies are macOS-only, so other platforms compile nothing extra. With `default-features = false`, macOS builds link the stub and return `ErrorCode::Unsupported`; add `features = ["vm"]` to keep the guest.

### Install CLI Tools

```bash
cargo install oci-builder
cargo install oci-runner
```

A macOS build embeds the guest from `crates/<crate>/guest/out/` when present. Otherwise it downloads the release's kernel and initramfs into `~/Library/Caches/<crate>/downloads` (override with `ROB_GUEST_CACHE` / `ROR_GUEST_CACHE`), verifies their checksums, and embeds them.

---

## Quick Start (Rust API)

### 1. Build an Image with `oci-builder`

```rust
use oci_builder::{startup, BuildRequest, Builder, Config, StorageDriver};

fn main() -> Result<(), oci_builder::Error> {
    // Early re-exec dispatch (mandatory on Linux)
    startup()?;

    let builder = Builder::open(Config {
        storage_driver: Some(StorageDriver::Vfs),
        ..Config::default()
    })?;

    let info = builder.build(
        BuildRequest::new("Dockerfile", ".")
            .with_tag("localhost/myapp:latest")
            .with_log(|r| eprintln!("{}", r.message)),
    )?;

    println!("Built image ID: {}", info.image_id);
    builder.shutdown()?;
    Ok(())
}
```

### 2. Run a Container with `oci-runner`

```rust
use oci_runner::{startup, RunRequest, Runtime};

fn main() -> Result<(), oci_runner::Error> {
    // Early re-exec dispatch (mandatory on Linux)
    startup()?;

    let runtime = Runtime::open()?;
    let request = RunRequest::new("/path/to/rootfs", ["/bin/sh", "-c", "echo Hello!"])
        .cwd("/")
        .hostname("runner")
        .isolate_network(true);

    let exit_code = runtime.run(&request)?;
    println!("Container exited with code: {exit_code}");

    runtime.shutdown()?;
    Ok(())
}
```

---

## CLI Usage

### `oci-builder` (Image Building)
```bash
# Check host readiness
oci-builder diagnose

# Build an image
oci-builder --storage-driver vfs \
  --signature-policy policy.json \
  build -f Dockerfile -t localhost/app:latest --isolation chroot

# Push an image
oci-builder --storage-driver vfs \
  --signature-policy policy.json \
  push localhost/app:latest localhost:5000/app:latest --insecure
```

### `oci-runner` (Container Running)
```bash
# Check host readiness
oci-runner diagnose

# Run a foreground container
oci-runner run --rootfs /path/to/rootfs -- /bin/echo "Running container!"

# Run with custom networking and working directory
oci-runner run --rootfs /path/to/rootfs --cwd /app --isolate-network -- /app/entrypoint.sh
```

---

## Repository Structure

```text
oci-lib/
├── Cargo.toml                  # Root workspace
├── .cargo/
│   └── config.toml             # macOS codesign wrapper configuration
├── scripts/
│   ├── entitlements.plist      # Virtualization entitlements
│   ├── macos-rustc-and-sign.sh
│   └── macos-sign-and-run.sh
├── xtask/                      # `cargo xtask guest`: builds the macOS Linux guest and holds its init scripts (run on Linux)
└── crates/
    ├── oci-builder/            # Buildah image builder crate (lib & CLI)
    │   ├── Cargo.toml
    │   ├── build.rs
    │   ├── guest/out/          # Built guest kernel and initramfs (not committed)
    │   ├── native/             # Early constructor
    │   ├── shim/               # Go Buildah c-archive shim
    │   ├── src/                # Library & CLI sources
    │   └── tests/
    └── oci-runner/             # libcontainer runtime crate (lib & CLI)
        ├── Cargo.toml
        ├── build.rs
        ├── guest/out/          # Built guest kernel and initramfs (not committed)
        ├── native/             # Early constructor
        ├── shim/               # Go libcontainer c-archive shim
        ├── src/                # Library & CLI sources
        └── tests/
```

---

## Development & Testing

### Building Locally
```bash
# Build the entire workspace
cargo build --workspace

# Run tests
cargo test --workspace

# macOS, without the Linux guest
cargo build --workspace --no-default-features
```

### Running on Linux
The Linux Go shims compile natively using CGO:
- Requires Go ≥ 1.26
- Requires C compiler (`gcc` or `clang`)
- Optional `libseccomp-dev` for seccomp filtering

### Codesigning on macOS
Apple Virtualization requires the `com.apple.security.virtualization` entitlement. Both crates embed it: when `startup()` finds the running binary without it (for example after `cargo install`, or in a crate that depends on these), it signs the executable ad hoc and re-executes it with the same arguments. Set `ROB_NO_SELF_SIGN=1` / `ROR_NO_SELF_SIGN=1` to turn that off; `diagnose` then prints the `codesign` command. If the binary's directory is not writable, signing is skipped and `diagnose` reports it.

In this repo, `cargo build`, `cargo test`, and `cargo run` also sign binaries through the scripts in [`.cargo/config.toml`](.cargo/config.toml), which covers test harnesses that never call `startup()`.

---

## Limitations

- **Early `startup()` Execution**: On Linux, `startup()` must be called as the very first line of `main()`, before any threads, async runtimes (e.g. Tokio), or CLI argument parsers are initialized. Both Buildah and libcontainer re-execute `/proc/self/exe` into isolated namespaces.
- **Platform Scope**: Full in-process execution is supported on Linux (native namespaces and cgroups) and macOS (via lightweight Apple Virtualization guests, the default `vm` feature). Other platforms (such as Windows), and macOS with `vm` turned off, link a stub returning `ErrorCode::Unsupported`.
- **Rootless & Kernel Namespace Support**: Non-root execution on Linux requires host kernel unprivileged user namespace support (`/proc/sys/kernel/unprivileged_userns_clone = 1` or configured `/etc/subuid` and `/etc/subgid` mappings).
- **Execution Scopes**:
  - `oci-builder`: Complex builds with `RUN` instructions require an OCI runtime (`runc` or `crun`) on `$PATH`.
  - `oci-runner`: Designed for synchronous foreground execution from an already prepared rootfs; it does not manage background daemon lifecycles or image pulling.
- **macOS Guest Boundary**: On macOS, both tools run their underlying engines inside an isolated Linux VM. Filesystem interactions across host and guest boundaries must pass through shared virtiofs directories.

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).
