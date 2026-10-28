#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Exercise actual AppArmor enforcement for init and exec on an enabled host.
# Usage: repro-apparmor.sh SOCKET ABSOLUTE_ARTIFACT_DIRECTORY
set -eu
socket=${1:?CRI socket required}
work=${2:?absolute artifact directory required}
case "$work" in /*) ;; *) echo 'artifact directory must be absolute' >&2; exit 2;; esac
mkdir -p "$work"
enabled=true
if [ ! -r /sys/module/apparmor/parameters/enabled ] || ! grep -q '^Y' /sys/module/apparmor/parameters/enabled; then
    enabled=false
fi
profile=oci-cri-regression-$$
pod=
cri() { crictl --runtime-endpoint "unix://$socket" "$@"; }
cleanup() {
    if [ -n "$pod" ]; then
        cri stopp "$pod" >> "$work/cleanup.log" 2>&1 || true
        cri rmp "$pod" >> "$work/cleanup.log" 2>&1 || true
    fi
    if [ "$enabled" = true ]; then
        apparmor_parser -R "$work/profile" >> "$work/cleanup.log" 2>&1 || true
    fi
}
trap cleanup EXIT
cat > "$work/profile" <<PROFILE
#include <tunables/global>
profile $profile flags=(attach_disconnected) {
  #include <abstractions/base>
  file,
  deny /tmp/oci-apparmor-blocked w,
}
PROFILE
modes=unconfined
if [ "$enabled" = true ]; then
    apparmor_parser -r -W "$work/profile"
    modes='deny unconfined privileged'
fi
image=docker.io/library/busybox:1.37.0
cri pull "$image" > "$work/pull.txt"
printf '%s\n' '{"metadata":{"name":"apparmor-regression","namespace":"default","uid":"apparmor-regression","attempt":0}}' > "$work/pod.json"
pod=$(cri runp "$work/pod.json")
for mode in $modes; do
    jq -n --arg mode "$mode" --arg profile "$profile" --arg image "$image" --arg log "$work/$mode.log" '{
        metadata:{name:$mode,attempt:0},image:{image:$image},log_path:$log,
        command:["sh","-c","if touch /tmp/oci-apparmor-blocked 2>/dev/null; then echo apparmor-write-allowed; else echo apparmor-write-denied; fi; sleep 3600"],
        linux:{security_context:{privileged:($mode=="privileged"),apparmor:
            (if $mode=="unconfined" then {profile_type:1} else {profile_type:2,localhost_ref:$profile} end)}}
    }' > "$work/$mode.json"
    id=$(cri create "$pod" "$work/$mode.json" "$work/pod.json")
    cri start "$id" > "$work/$mode.start.txt"
    expected=apparmor-write-allowed
    if [ "$mode" = deny ]; then expected=apparmor-write-denied; fi
    observed=false
    for attempt in $(seq 1 30); do
        if cri logs "$id" > "$work/$mode.init.txt" 2>&1 && grep -q "$expected" "$work/$mode.init.txt"; then
            observed=true
            break
        fi
        sleep 1
    done
    [ "$observed" = true ] || { cat "$work/$mode.init.txt"; exit 1; }
    if cri exec --sync "$id" touch /tmp/oci-apparmor-blocked > "$work/$mode.exec.txt" 2>&1; then
        [ "$mode" != deny ] || { echo 'AppArmor did not deny exec write' >&2; exit 1; }
    else
        [ "$mode" = deny ] || { cat "$work/$mode.exec.txt"; exit 1; }
        # A dead container or failed exec must not count as enforced policy.
        cri exec --sync "$id" cat /proc/self/attr/current > "$work/$mode.label.txt"
        grep -F "$profile (enforce)" "$work/$mode.label.txt" >/dev/null
    fi
    cri inspect "$id" > "$work/$mode.status.json"
done
if [ "$enabled" = true ]; then
    echo 'AppArmor denied init and exec writes; unconfined and privileged controls passed'
else
    echo 'AppArmor disabled on this host; Unconfined init and exec passed'
fi
