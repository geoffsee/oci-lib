#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# CRI conformance gate for oci-cri (Linux, root).
#
# Usage: scripts/cri-conformance.sh [socket] [critest-args...]
#   socket defaults to /run/oci-cri/oci-cri.sock; the runtime must already
#   be serving there (`oci-cri serve`). Requires crictl and critest from
#   cri-tools on PATH (https://github.com/kubernetes-sigs/cri-tools).
#
# Runs a set of crictl smoke checks, then the upstream CRI validation
# suite (critest). critest failures fail this script.

set -eu

SOCKET="${1:-/run/oci-cri/oci-cri.sock}"
shift 2>/dev/null || true
ENDPOINT="unix://$SOCKET"

command -v crictl >/dev/null 2>&1 || { echo "crictl not on PATH (install cri-tools)" >&2; exit 1; }
command -v critest >/dev/null 2>&1 || { echo "critest not on PATH (install cri-tools)" >&2; exit 1; }
[ -S "$SOCKET" ] || { echo "no CRI socket at $SOCKET — start: oci-cri serve --socket $SOCKET" >&2; exit 1; }

echo "== crictl info =="
crictl --runtime-endpoint "$ENDPOINT" info

echo "== crictl lifecycle smoke =="
crictl --runtime-endpoint "$ENDPOINT" pull registry.k8s.io/pause:3.10.1
crictl --runtime-endpoint "$ENDPOINT" images
POD_JSON='{"metadata":{"name":"conformance","namespace":"default","attempt":1,"uid":"conformance-uid"},"log_directory":"/tmp/oci-cri-logs","linux":{}}'
CTR_JSON='{"metadata":{"name":"pause","attempt":1},"image":{"image":"registry.k8s.io/pause:3.10.1"},"log_path":"pause.log","linux":{}}'
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT
printf '%s' "$POD_JSON" > "$TMPD/pod.json"
printf '%s' "$CTR_JSON" > "$TMPD/ctr.json"
POD_ID="$(crictl --runtime-endpoint "$ENDPOINT" runp "$TMPD/pod.json")"
# Both paths must finish the monitor and retain the actual exit status.
for STOP_TIMEOUT in 5 0; do
    CTR_ID="$(crictl --runtime-endpoint "$ENDPOINT" create "$POD_ID" "$TMPD/ctr.json" "$TMPD/pod.json")"
    crictl --runtime-endpoint "$ENDPOINT" start "$CTR_ID"
    crictl --runtime-endpoint "$ENDPOINT" stats -o json "$CTR_ID" > "$TMPD/stats.json"
    # A successful RPC with an empty list must not pass the metrics gate.
    grep -F "\"$CTR_ID\"" "$TMPD/stats.json" >/dev/null
    crictl --runtime-endpoint "$ENDPOINT" stop --timeout "$STOP_TIMEOUT" "$CTR_ID"
    crictl --runtime-endpoint "$ENDPOINT" inspect "$CTR_ID" > "$TMPD/status.json"
    grep -F '"CONTAINER_EXITED"' "$TMPD/status.json" >/dev/null
    EXPECTED_EXIT=0
    [ "$STOP_TIMEOUT" -ne 0 ] || EXPECTED_EXIT=137
    grep -E "\"exitCode\"[[:space:]]*:[[:space:]]*$EXPECTED_EXIT," "$TMPD/status.json" >/dev/null
    crictl --runtime-endpoint "$ENDPOINT" rm "$CTR_ID"
done
crictl --runtime-endpoint "$ENDPOINT" stopp "$POD_ID"
crictl --runtime-endpoint "$ENDPOINT" rmp "$POD_ID"
echo "crictl lifecycle smoke OK"

echo "== critest CRI validation suite =="
# --ginkgo.focus can be narrowed via extra args, e.g.:
#   scripts/cri-conformance.sh /run/oci-cri/oci-cri.sock --ginkgo.focus "runtime should"
critest --runtime-endpoint "$ENDPOINT" --image-endpoint "$ENDPOINT" "$@"
echo "CRI conformance OK"
