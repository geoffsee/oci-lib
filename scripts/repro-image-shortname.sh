#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Native CRI regression: short-name pull, lookup, creation, and removal without
# a host registry-search configuration. Run against a disposable runtime.
set -eu
socket=${1:?provide the CRI socket}
out=${2:?provide a new absolute artifact directory}
case "$out" in /*) ;; *) exit 2;; esac
mkdir "$out"
cri() { crictl --runtime-endpoint "unix://$socket" "$@"; }
pod=
id=
cleanup() {
    if [ -n "$id" ]; then cri rm -f "$id" >> "$out/cleanup.log" 2>&1 || true; fi
    if [ -n "$pod" ]; then
        cri stopp "$pod" >> "$out/cleanup.log" 2>&1 || true
        cri rmp "$pod" >> "$out/cleanup.log" 2>&1 || true
    fi
}
trap cleanup EXIT
cri pull busybox:1.36 > "$out/pull.txt" 2>&1
cri inspecti busybox:1.36 > "$out/short.json"
cri inspecti docker.io/library/busybox:1.36 > "$out/qualified.json"
image_id=$(jq -er '.status.id' "$out/short.json")
jq -e --arg id "$image_id" '.status.id == $id and (.status.repoTags | index("docker.io/library/busybox:1.36") != null)' "$out/qualified.json" >/dev/null
digest=$(jq -er '.status.repoDigests[0]' "$out/qualified.json")
cri inspecti "${digest#docker.io/library/}" > "$out/digest.json"
jq -e --arg id "$image_id" '.status.id == $id' "$out/digest.json" >/dev/null
jq -n --arg out "$out" --arg uid "shortname-$$" '{metadata:{name:$uid,namespace:"default",uid:$uid,attempt:0},log_directory:$out,linux:{security_context:{namespace_options:{network:2}}}}' > "$out/pod.json"
pod=$(cri runp "$out/pod.json")
jq -n '{metadata:{name:"shortname",attempt:0},image:{image:"busybox:1.36"},command:["sh","-c","echo short-name-started; sleep 300"],log_path:"shortname.log"}' > "$out/container.json"
id=$(cri create "$pod" "$out/container.json" "$out/pod.json")
cri start "$id" > "$out/start.txt" 2>&1
cri exec -s "$id" sh -c 'echo short-name-exec' > "$out/exec.txt"
grep -F short-name-exec "$out/exec.txt" >/dev/null
cri inspect "$id" > "$out/container-status.json"
jq -e '.status.state == "CONTAINER_RUNNING"' "$out/container-status.json" >/dev/null
cri logs "$id" > "$out/logs.txt"
grep -F short-name-started "$out/logs.txt" >/dev/null
cleanup
id=
pod=
cri rmi busybox:1.36 > "$out/remove.txt" 2>&1
cri images -o json > "$out/after-remove.json"
jq -e --arg id "$image_id" 'all(.images[]; .id != $id)' "$out/after-remove.json" >/dev/null
echo 'Short image names passed pull, status, digest lookup, create, exec, logs, and removal'
