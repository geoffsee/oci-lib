# CoreDNS startup reproducer

Captured on 2026-10-28 against oci-cri `446538dcf5ee32d714e6484cfa00032314f0c590`,
embedded in diorama, on Linux arm64 in a Debian Bookworm container with a private
cgroup namespace. CoreDNS image: `docker.io/coredns/coredns:1.14.4`; captured
manifest digest: `sha256:3e98f280fd601b37411c5fb7075fd9f337833c480f1644970b727ae0af067782`.
The script records the actual image metadata on each run.

## Fast regression

```sh
cargo test -p oci-cri --lib args_only_preserves_coredns_image_entrypoint
```

This regression test now passes. It calls the real
CRI-to-OCI spec conversion with an image entrypoint of `/coredns` and only
container arguments `-version`. Expected process arguments are
`["/coredns", "-version"]`; the previous implementation produced `["-version"]`.
It needs no Linux VM, registry, kubelet, or network.

Kubernetes specifies that args without command retain the image entrypoint:
https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/

## Native reproduction

Use a disposable native Linux oci-cri runtime with a writable delegated domain
cgroup hierarchy. Run it as PID 1 if containerized; run the client in a separate
container sharing the runtime socket and artifact directory. See the crate's
README for runtime setup. The script requires `crictl` and `jq`.

Install the runtime binary as a regular file inside a test container (for
example, `docker cp` into a created container). A single-file bind mount over
the executable is incompatible with runc 1.5.2's sealed overlay clone of its
parent directory: the clone sees the underlying empty mountpoint rather than
the mounted binary. This reproduced as `exec format error` locally and
`permission denied` in CI. Copying the same binary into the container fixes the
fixture without changing the workload or its security settings.

```sh
scripts/repro-coredns-start.sh /run/oci-cri/oci-cri.sock /shared/coredns-run-1
```

The output directory must be new, absolute, and visible at the same path to both
runtime and client. Parent directories must exist. The script uses host
networking and CoreDNS's `-version` command: no CNI, Corefile, DNS server,
Kubernetes API, or pod DNS lookup is involved. Image pulls still require registry
access. `COREDNS_IMAGE` can select another image with the same `/coredns` entrypoint.

The script creates and cleans up only its own sandbox and containers, preserves
artifacts after failure, and exits nonzero if any case fails to print a CoreDNS
version and exit 0. It records first-start errors separately from retries.

| Case | Configuration | Observed result |
| --- | --- | --- |
| inherited | args only, explicit CAP_NET_BIND_SERVICE | First start tries to execute `-version` and fails; retry says `container already has init process` |
| explicit | `/coredns -version`, explicit CAP_NET_BIND_SERVICE | Prints `CoreDNS-1.14.4`, exits 0 |
| no-capabilities | `/coredns -version`, omitted capabilities | Start RPC succeeds, process logs `exec /coredns: operation not permitted`, exits 255 |

The missing entrypoint is reproducible independently of DNS. The retry error is
secondary to a failed initial start. An explicit executable alone is insufficient:
the capabilities case must also be handled. The successful control demonstrates
that this image can execute in the same runtime environment with the capability
supplied; it does not establish DNS correctness or full Kubernetes compatibility.

## Fixes and validation

The fixes preserve the image entrypoint for args-only requests, supply the
containers-common default capability set, normalize capability names, honor
add/drop/ambient requests, and recreate libcontainer state after failed starts.
The script now expects inherited, explicit, and default-capability cases to exit
0. It also starts a deliberately missing executable three times and requires the
original error each time, followed by successful removal. The native suite passed
on Linux arm64. CI runs it in a private delegated cgroup and retains artifacts.

Full-node validation also exposed resolver propagation: the host resolv.conf
mount hid the sandbox DNS settings. The runtime now writes an owned resolver
file per sandbox and binds it into infra and workload containers. It persists
across daemon restarts and is removed with the sandbox. File creation errors
are propagated, and aborted setup removes the resolver file. Regression tests
cover generated contents, workload mounts, removal, invalid tokens, and I/O errors.

Diorama's native smoke now checks normal pod DNS resolution without explicitly
supplying a DNS server, alongside networking, exec, logs, stats, resources, and
cleanup. Seccomp enforcement remains unsupported; this is not a conformance claim.

## Threaded init state regression

Storage validation exposed a separate process-state race. During Linux exec's
`de_thread`, the Go init's original thread can appear as `runc:[2:INIT] Z` while
another thread is replacing it. Reading procfs at that moment marked a live
workload Exited with code -1, or made sandbox setup fail with "container still
running". The captured writer continued running and its volume write succeeded.

Owned child processes now have one wait goroutine. State, exit status, signals,
and removal share that wait result; sandbox children are reaped too. Reloaded
containers still use libcontainer's persisted state because they are not owned
children of the new daemon.

```sh
scripts/repro-threaded-init.sh /run/oci-cri/oci-cri.sock /shared/threaded-run-1
```

This requires `cc` with static pthread support in addition to `crictl` and `jq`.
The fixture deliberately exits its initial thread while another thread remains
alive. CRI must report Running until that worker is released, then report exit
42 and retain its output. The same fixture failed before the fix and passed
afterward on Linux arm64. CI runs it alongside the startup regression.
