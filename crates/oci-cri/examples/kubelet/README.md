# Pointing a kubelet at `oci-cri`

`oci-cri` is distro-agnostic CRI. Any kubelet that accepts a CRI unix socket
can use it.

## Serve

```sh
sudo oci-cri serve \
  --socket /var/run/cri.sock \
  --root /var/lib/oci-cri \
  --sandbox-image registry.k8s.io/pause:3.10.1 \
  --cni-bin-dir /opt/cni/bin \
  --cni-conf-dir /etc/cni/net.d
```

Or depend on the library and call
`oci_cri::server::serve(Config { … })` from your own binary.

## Wire the kubelet

| Distro | Typical flag / config |
| --- | --- |
| **kubeadm / vanilla** | kubelet `--container-runtime-endpoint=unix:///var/run/cri.sock` |
| **k3s / RKE2** | Disable embedded containerd; set the agent/kubelet CRI endpoint to this socket; own CNI dirs carefully |
| **MicroK8s** | Snap paths differ; override socket/root and confinement as needed |
| **OpenShift** | Needs extra SELinux/SCC work beyond this library today |

Supply CNI plugins and at least one conflist before `RunPodSandbox`. Pre-pull
the pause image to avoid first-pod latency.

## Verify

```sh
export CRI="--runtime-endpoint unix:///var/run/cri.sock"
crictl $CRI info
scripts/cri-conformance.sh /var/run/cri.sock
```
