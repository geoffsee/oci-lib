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
