# oci-runner

[![Crates.io](https://img.shields.io/crates/v/oci-runner.svg)](https://crates.io/crates/oci-runner)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

Rust library (`oci_runner`) and CLI (`oci-runner`) for running foreground containers with embedded [libcontainer](https://github.com/opencontainers/runc/tree/main/libcontainer). There is no `runc`, `crun`, or `podman` executable required on `$PATH`.

- **Linux**: Executes containers in-process via a statically linked Go C-archive (`-buildmode=c-archive`) with priority 101 `nsexec` constructor, custom seccomp filtering, and native Linux namespaces.
- **macOS** (default `vm` feature): Boots a lightweight Linux guest through Apple's Virtualization framework and coordinates execution over virtio-vsock (port 5253).
- **Other OSes**: Links a lightweight stub returning `ErrorCode::Unsupported`.

---

## Installation

### Add as a Library Dependency

```toml
[dependencies]
oci-runner = "0.1"
```

### Install CLI Binary

```bash
cargo install oci-runner
```

---

## Rust Library Usage

> [!IMPORTANT]
> On Linux, `startup()` **must** be called at the very beginning of `main()`, before spawning threads, Tokio runtimes, or parsing CLI arguments. `libcontainer` re-executes `/proc/self/exe` into namespaces to initialize the container.

```rust
use oci_runner::{startup, RunRequest, Runtime};

fn main() -> Result<(), oci_runner::Error> {
    // 1. Mandatory re-exec dispatch
    startup()?;

    // 2. Open runtime instance
    let runtime = Runtime::open()?;

    // 3. Configure and run the container
    let request = RunRequest::new("/path/to/rootfs", ["/bin/echo", "hello world"])
        .cwd("/")
        .hostname("runner")
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        .isolate_network(true);

    let exit_code = runtime.run(&request)?;
    println!("Container exited with code: {exit_code}");

    // 4. Shutdown runtime
    runtime.shutdown()?;
    Ok(())
}
```

### Capturing Container Output
You can stream stdout and stderr via `run_with`:
```rust
use std::sync::Arc;

let on_output = Arc::new(|stream: u8, data: &[u8]| {
    if stream == 1 {
        print!("{}", String::from_utf8_lossy(data));
    } else {
        eprint!("{}", String::from_utf8_lossy(data));
    }
});

let exit_code = runtime.run_with(&request, Some(on_output))?;
```

---

## CLI Usage

### Check Host Prerequisites
```bash
oci-runner diagnose
```

### Run a Container Rootfs
```bash
oci-runner run --rootfs /path/to/rootfs -- /bin/sh -c "echo Hello from container!"
```

With custom flags:
```bash
oci-runner run \
  --rootfs /path/to/rootfs \
  --cwd /app \
  --hostname runner-pod \
  --isolate-network \
  -e FOO=bar \
  -- /app/start.sh
```

---

## Build Requirements

- **Linux**: Go ≥ 1.26, C compiler (`gcc` or `clang`), `pkg-config`, and optionally `libseccomp-dev`.
- **macOS**: Built-in Apple Virtualization framework. Codesigning is automatically handled via `.cargo/config.toml` with the `com.apple.security.virtualization` entitlement.

---

## Limitations

- **Process Re-execution Hook**: On Linux, `startup()` must execute at the very entrypoint of `main()`. `libcontainer` spawns container processes by re-executing `/proc/self/exe`. If called after Tokio runtimes, thread pools, or signal handlers are established, initialization hangs or aborts.
- **Foreground Execution Only**: `oci-runner` is designed for synchronous, foreground execution (`run` waits for the container process to exit). It does not manage long-running background container daemons, detachment, or state persistence across host reboots.
- **Rootfs Preparation**: Does not include an image puller or layer unpacker. The container rootfs directory must be unpacked and mounted prior to invoking `RunRequest::new(rootfs, ...)`.
- **Not a Complete OCI CLI**: `oci-runner` implements `diagnose` and `run`. It is not a drop-in replacement for the multi-command OCI runtime specification (`create`, `start`, `kill`, `delete`, `state`).
- **macOS Host Isolation**: On macOS, containers run in a Linux Virtualization guest kernel. They do not share the host macOS kernel or network interfaces directly; host filesystems must be shared via virtiofs.
- **Linux Privilege Requirements**: In-process namespace isolation requires either `root` privileges or unprivileged user namespace support enabled in the host kernel (`/proc/sys/kernel/unprivileged_userns_clone = 1`). Mounting certain filesystems or creating devices requires appropriate Linux capabilities.
- **Platform Support**: Fully supported on Linux and macOS (the default `vm` feature embeds the Apple Virtualization guest). Other operating systems, and macOS with `vm` turned off, link a stub implementation that returns `ErrorCode::Unsupported`.
