#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Native init/exec seccomp regression. Requires cc, jq, crictl and an artifact
# path shared with a disposable Linux runtime.
set -eu
socket=${1:?provide the CRI socket}
out=${2:?provide a new absolute artifact directory}
case "$out" in /*) ;; *) exit 2;; esac
mkdir "$out"
cri() { crictl --runtime-endpoint "unix://$socket" "$@"; }
id=
pod=
cleanup() {
    if [ -n "$id" ]; then cri rm -f "$id" >> "$out/cleanup.log" 2>&1 || true; fi
    if [ -n "$pod" ]; then cri stopp "$pod" >> "$out/cleanup.log" 2>&1 || true; cri rmp "$pod" >> "$out/cleanup.log" 2>&1 || true; fi
}
trap cleanup EXIT
cat > "$out/probe.c" <<'C'
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    errno = 0;
    long result = syscall(SYS_getsid, 0);
    int denied = result == -1 && errno == EPERM;
    if (denied != (strcmp(argv[1], "deny") == 0)) return 3;
    int filter = prctl(PR_GET_SECCOMP);
    if (strcmp(argv[1], "default") == 0 && filter != 2) return 4;
    printf("getsid=%s seccomp=%d\n", denied ? "denied" : "allowed", filter);
    fflush(stdout);
    if (argc > 2) for (;;) pause();
    return 0;
}
C
cc -static -O2 -o "$out/probe" "$out/probe.c"
printf '%s\n' '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["getsid"],"action":"SCMP_ACT_ERRNO","errnoRet":1}]}' > "$out/profile.json"
image=registry.k8s.io/e2e-test-images/busybox:1.29-2
cri pull "$image" > "$out/pull.txt" 2>&1
jq -n --arg out "$out" --arg uid "seccomp-$$" '{metadata:{name:$uid,namespace:"default",uid:$uid,attempt:0},log_directory:$out,linux:{security_context:{namespace_options:{network:2}}}}' > "$out/pod.json"
pod=$(cri runp "$out/pod.json")
for mode in allow deny default privileged; do
    jq -n --arg mode "$mode" --arg out "$out" --arg image "$image" '{metadata:{name:$mode,attempt:0},image:{image:$image},command:["/fixture/probe",(if $mode == "privileged" then "allow" else $mode end),"wait"],log_path:($mode+".log"),mounts:[{container_path:"/fixture",host_path:$out}],linux:{security_context:{privileged:($mode=="privileged"),seccomp:(if $mode=="allow" then {profile_type:1} elif $mode=="default" then {profile_type:0} else {profile_type:2,localhost_ref:($out+"/profile.json")} end)}}}' > "$out/container-$mode.json"
    id=$(cri create "$pod" "$out/container-$mode.json" "$out/pod.json")
    cri start "$id" > "$out/start-$mode.txt" 2>&1
    ready=false
    for attempt in $(seq 1 20); do
        cri logs "$id" > "$out/init-$mode.txt" 2>&1
        if grep -q getsid= "$out/init-$mode.txt"; then ready=true; break; fi
        sleep 1
    done
    [ "$ready" = true ]
    cri inspect "$id" > "$out/status-$mode.json"
    jq -e '.status.state == "CONTAINER_RUNNING"' "$out/status-$mode.json" >/dev/null
    expected=$mode
    [ "$mode" != privileged ] || expected=allow
    cri exec --sync "$id" /fixture/probe "$expected" > "$out/exec-$mode.txt" 2>&1
    grep -q getsid= "$out/exec-$mode.txt"
    cri rm -f "$id" >> "$out/cleanup.log" 2>&1
    id=
done
# Missing and malformed Localhost profiles must fail at create.
for profile in missing malformed; do
    printf '%s' '{' > "$out/malformed.json"
    jq --arg path "$out/$profile.json" '.linux.security_context.privileged=false | .linux.security_context.seccomp={profile_type:2,localhost_ref:$path}' "$out/container-deny.json" > "$out/invalid-$profile.json"
    if cri create "$pod" "$out/invalid-$profile.json" "$out/pod.json" > "$out/invalid-$profile.txt" 2>&1; then
        echo "Accepted $profile seccomp policy" >&2; exit 1
    fi
done
echo 'Seccomp enforced for init and exec; unconfined and privileged controls passed; invalid profiles rejected'
