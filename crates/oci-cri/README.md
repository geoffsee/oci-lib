# `oci-cri` — vendor-agnostic CRI v1 runtime

`oci-cri` is a [Container Runtime Interface](https://kubernetes.io/docs/concepts/architecture/cri/)
(CRI v1) runtime: kubelet talks CRI over a unix socket to this daemon instead
of containerd, dockerd, or CRI-O. Containers run with libcontainer (via an
in-process Go c-archive); images come from containers/image + containers/storage.

```
kubelet (--container-runtime-endpoint / --cri-socket)
  └── oci-cri          CRI RuntimeService + ImageService (this crate)
        └── Go shim    libcontainer + containers/image & storage
```

## Quick start (Linux)

```sh
cargo build -p oci-cri
sudo target/debug/oci-cri diagnose
sudo target/debug/oci-cri serve \
  --socket /run/oci-cri/oci-cri.sock \
  --root /var/lib/oci-cri \
  --sandbox-image registry.k8s.io/pause:3.10.1 \
  --cni-bin-dir /opt/cni/bin \
  --cni-conf-dir /etc/cni/net.d
```

On cgroup v2, provide a writable delegated domain hierarchy. In a private
cgroup namespace, the root must be empty or contain only the runtime process.
On first container creation the runtime moves itself into an
`oci-cri-runtime-<pid>` leaf, then enables controllers for sibling workload
cgroups. It rejects shared or already threaded roots before libcontainer can
convert the hierarchy to threaded mode. Run a containerized daemon directly as
PID 1; run diagnostic clients outside its cgroup. Existing diorama host setup
can supply an empty root with the runtime already in its `init` leaf.

Point any CRI-capable kubelet at the socket (see
[`examples/kubelet/`](examples/kubelet/)):

```sh
# kubeadm / vanilla
kubelet --container-runtime-endpoint=unix:///run/oci-cri/oci-cri.sock ...

# crictl
crictl --runtime-endpoint unix:///run/oci-cri/oci-cri.sock info
```

## Library usage

```rust,ignore
use oci_cri::{Config, startup};
use oci_cri::server;

fn main() -> Result<(), oci_cri::Error> {
    startup()?;
    let config = Config {
        runtime_name: "my-runtime".into(),
        socket: "/run/my-runtime/cri.sock".into(),
        root: "/var/lib/my-runtime".into(),
        state_root: "/run/my-runtime/state".into(),
        ..Config::default()
    };
    server::serve(config)
}
```

Defaults use the neutral `oci-cri` layout (`/run/oci-cri/...`). Override
`runtime_name` and paths for product branding.

For Linux embedding into an existing async executor, call
`server::serve_until(config, shutdown_future).await` after early `startup()`.
The shutdown future resolves to `()`. The server drains in-flight CRI RPCs,
closes its streaming listener, and removes its socket. It does not stop
workload containers; the orchestrator must apply its workload shutdown policy
first. `serve_with_engine_until` provides the same lifecycle for an explicit
engine, including the test engine. Streaming bind errors fail startup before
the CRI socket becomes visible. A supervisor should bound the shutdown wait
because outstanding RPCs may take time to drain.

## Surface

Full CRI v1: pod/container lifecycle, Exec/Attach/PortForward streaming,
CRI logs, stats, ImageService (pull/list/status/remove/`ImageFsInfo`), and
CNI networking via `--cni-bin-dir` / `--cni-conf-dir`.

Conformance: [`scripts/cri-conformance.sh`](../../scripts/cri-conformance.sh)
and this crate's `cri_lifecycle` / `streaming_exec` tests.

## Distro notes

| Distro | Typical wiring |
| --- | --- |
| kubeadm / vanilla | `--container-runtime-endpoint=unix://…` |
| k3s / RKE2 | Disable embedded containerd; point the agent at this socket |
| MicroK8s | Override snap paths / confinement |
| OpenShift | Needs extra SELinux/SCC work beyond this crate today |

Supply CNI plugins and a pause image on disk before the first pod.

Seccomp profile enforcement is not implemented. Requests for `RuntimeDefault`,
`Localhost`, or a legacy confined profile are rejected as unsupported; they are
never silently downgraded to unconfined. Explicit `Unconfined` and unspecified
profiles retain the existing behavior. Enabling the build's libseccomp feature
alone does not implement CRI profile translation.

## macOS

Without `vm`, macOS links the engine stub (`ErrorCode::Unsupported`).

With `--features vm`, macOS boots an embedded Linux guest via
[`oci_util::vm`](../oci-util) and proxies each host CRI unix connection over
virtio-vsock (port 5254, banner `ROKCRI1`) to `oci-cri --engine-serve` inside
the guest. Build the guest on Linux with `cargo xtask guest oci-cri` (or let
the release download cache supply images once published). Until those artifacts
exist, keep `vm` opt-in so plain workspace builds stay green.

MVP limits: CNI is disabled in the guest (sandboxes share the guest netns);
Exec/Attach streaming URLs are not rewritten to the host, so kubelet streaming
against a Mac-hosted socket is not supported yet.

## Container startup and DNS

Args-only CRI requests retain the image entrypoint; an explicit command replaces
it. Unprivileged workloads start with the containers-common default capabilities
(CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, NET_BIND_SERVICE, SETFCAP, SETGID,
SETPCAP, SETUID, SYS_CHROOT). CRI additions and drops accept names with or without
`CAP_`; `drop: ALL` clears defaults before explicit additions. Ambient requests
are handled separately. Defaults do not include SYS_ADMIN or NET_RAW.

Sandbox DNS settings are mounted from runtime-owned resolver files into each
workload, rather than shadowed by the host resolver. Failed initial starts clean
up libcontainer state before a retry, retaining the original error.

See [the CoreDNS regression guide](../../docs/repros/coredns-start.md) and
[`scripts/repro-coredns-start.sh`](../../scripts/repro-coredns-start.sh) for the
native regression gate. The script preserves diagnostics and exits nonzero on
startup, retry, or removal failures.
