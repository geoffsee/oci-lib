#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Requires a disposable Linux oci-cri runtime, crictl, and jq.
# Usage: scripts/repro-coredns-start.sh SOCKET NEW_ARTIFACT_DIRECTORY
# The artifact directory must be visible at the same path to the runtime.
# Uses host networking: neither CNI nor DNS resolution inside a pod is needed.
set -eu
socket=${1:?provide the CRI socket}
out=${2:?provide a new absolute artifact directory}
case "$out" in /*) ;; *) echo 'Artifact directory must be absolute' >&2; exit 2;; esac
mkdir "$out"
image=${COREDNS_IMAGE:-docker.io/coredns/coredns:1.14.4}
cri() { crictl --runtime-endpoint "unix://$socket" --image-endpoint "unix://$socket" "$@"; }
pod=
ids=
cleanup() {
    for id in $ids; do
        cri stop --timeout 0 "$id" >> "$out/cleanup.log" 2>&1 || true
        cri rm -f "$id" >> "$out/cleanup.log" 2>&1 || true
    done
    if [ -n "$pod" ]; then
        cri stopp "$pod" >> "$out/cleanup.log" 2>&1 || true
        cri rmp "$pod" >> "$out/cleanup.log" 2>&1 || true
    fi
}
trap cleanup EXIT
cri version > "$out/version.txt"
cri info > "$out/info.json"
cri pull "$image" > "$out/pull.txt" 2>&1
cri inspecti "$image" > "$out/image.json"
jq -n --arg logs "$out" --arg uid "coredns-repro-$$" '{metadata:{name:$uid,namespace:"default",uid:$uid,attempt:0},log_directory:$logs,linux:{security_context:{namespace_options:{network:2}}}}' > "$out/pod.json"
pod=$(cri runp "$out/pod.json")
printf '%s\n' "$pod" > "$out/pod-id"
failed=0
for mode in inherited explicit defaults; do
    jq -n --arg image "$image" --arg mode "$mode" '{metadata:{name:$mode,attempt:0},image:{image:$image},args:["-version"],log_path:($mode+".log"),linux:(if $mode == "defaults" then {} else {security_context:{capabilities:{add_capabilities:["CAP_NET_BIND_SERVICE"]}}} end)} + (if $mode != "inherited" then {command:["/coredns"]} else {} end)' > "$out/$mode.json"
    id=$(cri create "$pod" "$out/$mode.json" "$out/pod.json")
    ids="$ids $id"
    printf '%s\n' "$id" > "$out/$mode.id"
    cri inspect "$id" > "$out/$mode.before.json"
    if cri start "$id" > "$out/$mode.first-start.txt" 2>&1; then
        exited=false
        for attempt in $(seq 1 30); do
            cri inspect "$id" > "$out/$mode.after.json"
            if jq -e '.status.state == "CONTAINER_EXITED"' "$out/$mode.after.json" >/dev/null; then
                exited=true
                break
            fi
            sleep 1
        done
        if [ "$exited" != true ] || ! jq -e '.status.exitCode == 0' "$out/$mode.after.json" >/dev/null; then
            failed=1
        fi
        cri logs "$id" > "$out/$mode.output.txt" 2>&1 || true
        grep -F 'CoreDNS-' "$out/$mode.output.txt" >/dev/null || failed=1
    else
        failed=1
        cri inspect "$id" > "$out/$mode.after.json"
        # Capture the misleading retry separately, never overwrite the first error.
        cri start "$id" > "$out/$mode.retry.txt" 2>&1 || true
    fi
    printf '%s process: ' "$mode"
    jq -c '.spec.process.args' "$out/$mode.before.json"
    cat "$out/$mode.first-start.txt"
    jq -c '.status | {state,exitCode}' "$out/$mode.after.json"
    if [ -f "$out/$mode.output.txt" ]; then cat "$out/$mode.output.txt"; fi
done
# An invalid executable must fail consistently, without poisoning the handle.
jq -n --arg image "$image" '{metadata:{name:"invalid",attempt:0},image:{image:$image},command:["/definitely-missing-oci-cri-repro"],log_path:"invalid.log",linux:{}}' > "$out/invalid.json"
id=$(cri create "$pod" "$out/invalid.json" "$out/pod.json")
ids="$ids $id"
for attempt in 1 2 3; do
    if cri start "$id" > "$out/invalid.start-$attempt.txt" 2>&1; then
        echo 'Invalid executable unexpectedly started' >&2
        failed=1
    fi
    grep -E 'executable file not found|no such file or directory' "$out/invalid.start-$attempt.txt" >/dev/null || failed=1
    if grep -F 'already has init process' "$out/invalid.start-$attempt.txt" >/dev/null; then failed=1; fi
    cri inspect "$id" > "$out/invalid.after-$attempt.json"
    jq -e '.status.state == "CONTAINER_CREATED"' "$out/invalid.after-$attempt.json" >/dev/null || failed=1
done
# Explicit removal must work after repeated failed starts.
cri rm -f "$id" > "$out/invalid.remove.txt" 2>&1 || failed=1
printf 'Artifacts: %s\n' "$out"
exit "$failed"
