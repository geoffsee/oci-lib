#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Requires Linux, cc with static pthread support, crictl, jq, and a disposable
# runtime. The new artifact directory must be visible at the same absolute path
# to the runtime. An exited thread-group leader is not an exited process.
set -eu
socket=${1:?provide the CRI socket}
out=${2:?provide a new absolute artifact directory}
case "$out" in /*) ;; *) exit 2;; esac
mkdir "$out"
cri() { crictl --runtime-endpoint "unix://$socket" "$@"; }
id=
pod=
cleanup() {
    touch "$out/release"
    if [ -n "$id" ]; then cri rm -f "$id" >> "$out/cleanup.log" 2>&1 || true; fi
    if [ -n "$pod" ]; then
        cri stopp "$pod" >> "$out/cleanup.log" 2>&1 || true
        cri rmp "$pod" >> "$out/cleanup.log" 2>&1 || true
    fi
}
trap cleanup EXIT
cat > "$out/threaded-init.c" <<'EOF'
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void *worker(void *unused) {
    (void)unused;
    usleep(250000); /* Let the initial thread exit before signalling readiness. */
    FILE *ready = fopen("/fixture/ready", "w");
    if (!ready) _Exit(2);
    fclose(ready);
    while (access("/fixture/release", F_OK) != 0) usleep(10000);
    puts("threaded-init-completed");
    fflush(stdout);
    _Exit(42);
}
int main(void) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) != 0) return 3;
    pthread_exit(NULL);
}
EOF
cc -static -pthread -O2 -o "$out/threaded-init" "$out/threaded-init.c"
image=${COREDNS_IMAGE:-docker.io/coredns/coredns:1.14.4}
cri pull "$image" > "$out/pull.txt" 2>&1
jq -n --arg out "$out" --arg uid "threaded-init-$$" '{metadata:{name:$uid,namespace:"default",uid:$uid,attempt:0},log_directory:$out,linux:{security_context:{namespace_options:{network:2}}}}' > "$out/pod.json"
pod=$(cri runp "$out/pod.json")
jq -n --arg image "$image" --arg out "$out" '{metadata:{name:"threaded",attempt:0},image:{image:$image},command:["/fixture/threaded-init"],log_path:"threaded.log",mounts:[{container_path:"/fixture",host_path:$out}],linux:{}}' > "$out/container.json"
id=$(cri create "$pod" "$out/container.json" "$out/pod.json")
cri start "$id" > "$out/start.txt" 2>&1
for attempt in $(seq 1 30); do [ -f "$out/ready" ] && break; sleep 1; done
test -f "$out/ready"
for attempt in 1 2 3; do
    cri inspect "$id" > "$out/running-$attempt.json"
    jq -e '.status.state == "CONTAINER_RUNNING"' "$out/running-$attempt.json" >/dev/null
done
touch "$out/release"
exited=false
for attempt in $(seq 1 30); do
    cri inspect "$id" > "$out/exited.json"
    if jq -e '.status.state == "CONTAINER_EXITED" and .status.exitCode == 42' "$out/exited.json" >/dev/null; then
        exited=true
        break
    fi
    sleep 1
done
[ "$exited" = true ]
cri logs "$id" > "$out/output.txt"
grep -F threaded-init-completed "$out/output.txt" >/dev/null
echo 'Threaded init stayed Running until process exit; exit code and output preserved'
