#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Reproducible Linux conformance fixture. The client joins the runtime's
# namespaces but keeps its own cgroup, leaving the delegated root empty.
# Usage: CONTAINER_ENGINE=docker scripts/native-cri-conformance.sh BINARY OUTPUT
set -eu
engine=${CONTAINER_ENGINE:-docker}
binary=${1:?provide the native Linux oci-cri binary}
out=${2:?provide a new absolute artifact directory}
case "$out" in /*) ;; *) echo 'output must be absolute' >&2; exit 2;; esac
mkdir -p "$out/fixture" "$out/tools"
name="oci-cri-conformance-$$"
image="$name:local"
client="$name-client"
cleanup() {
    "$engine" logs "$name" > "$out/runtime.log" 2>&1 || true
    "$engine" cp "$name:/evidence/." "$out/" || true
    "$engine" rm -f "$client" "$name" >/dev/null 2>&1 || true
    "$engine" image rm "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cat > "$out/fixture/Dockerfile" <<'DOCKER'
FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq libseccomp2 iproute2 iptables ca-certificates apparmor sudo jq gcc libc6-dev util-linux && rm -rf /var/lib/apt/lists/*
DOCKER
"$engine" build -t "$image" "$out/fixture" > "$out/image-build.log" 2>&1
arch=$("$engine" run --rm "$image" uname -m)
case "$arch" in x86_64) arch=amd64;; aarch64) arch=arm64;; *) echo "Unsupported architecture: $arch" >&2; exit 2;; esac
for tool in crictl critest; do
    if [ ! -x "$out/tools/$tool" ]; then
        curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.32.0/$tool-v1.32.0-linux-$arch.tar.gz" | tar -xz -C "$out/tools"
    fi
done
mkdir -p "$out/tools/cni"
if [ ! -x "$out/tools/cni/bridge" ]; then
    curl -fsSL "https://github.com/containernetworking/plugins/releases/download/v1.6.2/cni-plugins-linux-$arch-v1.6.2.tgz" | tar -xz -C "$out/tools/cni"
fi
"$engine" create --name "$name" --privileged --cgroupns private --pids-limit=-1 "$image" /usr/local/bin/oci-cri serve --socket /tmp/cri.sock --root /var/lib/oci-cri --cni-bin-dir /opt/cni/bin --cni-conf-dir /etc/cni/net.d >/dev/null
"$engine" cp "$binary" "$name:/usr/local/bin/oci-cri"
for tool in crictl critest; do "$engine" cp "$out/tools/$tool" "$name:/usr/local/bin/$tool"; done
"$engine" start "$name" >/dev/null
"$engine" exec "$name" mkdir -p /opt/cni/bin /etc/cni/net.d /evidence
# A fresh container sysfs may omit the securityfs submount needed by the
# AppArmor loader and by the runtime's loaded-profile checks.
"$engine" exec "$name" sh -ec '
    if [ -r /sys/module/apparmor/parameters/enabled ] && grep -q "^Y" /sys/module/apparmor/parameters/enabled; then
        mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security
    fi
'
"$engine" cp "$out/tools/cni/." "$name:/opt/cni/bin/"
"$engine" exec -i "$name" sh -c 'cat > /etc/cni/net.d/10-test.conflist' <<'CNI'
{"cniVersion":"1.0.0","name":"oci-conformance","plugins":[{"type":"bridge","bridge":"cri-test0","isGateway":true,"ipMasq":true,"ipam":{"type":"host-local","ranges":[[{"subnet":"10.87.0.0/24"}]],"routes":[{"dst":"0.0.0.0/0"}]}},{"type":"portmap","capabilities":{"portMappings":true}}]}
CNI
for script in cri-conformance repro-seccomp repro-apparmor repro-coredns-start repro-threaded-init; do "$engine" cp "scripts/$script.sh" "$name:/usr/local/bin/$script"; done
# nsenter joins IPC below. Docker's private IPC namespaces cannot be joined
# through --ipc=container unless the donor was created as shareable.
"$engine" run -d --name "$client" --privileged --network "container:$name" --pid "container:$name" "$image" sleep infinity >/dev/null
"$engine" exec "$client" nsenter -t 1 -m -u -i sh -ec '
    for attempt in $(seq 1 60); do crictl --runtime-endpoint unix:///tmp/cri.sock info > /evidence/info.json 2>/dev/null && break; sleep 1; done
    test -s /evidence/info.json
    repro-seccomp /tmp/cri.sock /evidence/seccomp > /evidence/seccomp.log 2>&1
    repro-apparmor /tmp/cri.sock /evidence/apparmor > /evidence/apparmor.log 2>&1
    repro-coredns-start /tmp/cri.sock /evidence/coredns > /evidence/coredns.log 2>&1
    repro-threaded-init /tmp/cri.sock /evidence/threaded > /evidence/threaded.log 2>&1
    cri-conformance /tmp/cri.sock --ginkgo.v --ginkgo.junit-report=/evidence/conformance.xml > /evidence/conformance.log 2>&1
'
echo "Native CRI regression and conformance checks passed; evidence: $out"
