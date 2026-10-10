# Example build contexts

Each subdirectory is a context for `oci-builder build`. The successful ones use `FROM scratch`, so they do not pull a base image and do not need runc or crun. On Linux:

```bash
oci-builder \
  --root /tmp/rob-graph --runroot /tmp/rob-run --storage-driver vfs \
  --signature-policy /tmp/policy.json \
  build --context examples/scratch-copy -t localhost/scratch-copy:latest \
  --pull never --isolation chroot
```

`/tmp/policy.json` for a local store that does not verify signatures:

```json
{"default":[{"type":"insecureAcceptAnything"}]}
```

On macOS, the build embeds the Linux guest into the binary. It uses `guest/out/` when present (built with `cargo xtask guest` on arm64 Linux), and otherwise downloads this version's kernel and initramfs into `~/Library/Caches/<crate>/downloads` and verifies them. `cargo run -p oci-builder --` signs the binary and can run the same command. The guest is root, uses the `vfs` driver, and does not include `runc`, so keep `--isolation chroot` and `--pull never` for this image.

Podman uses its own store. The [CLI](../README.md#cli) section shows how to `push` a tag to a `docker-archive` and `podman load` it. On macOS, write that archive under `/mnt/policy` (the guest's view of the `--signature-policy` directory) so the tar remains on the Mac after the VM exits. `scratch-copy` contains only `/hello.txt`. `podman cp` writes a tar stream, and `tar -xO` prints `hello`.

| Directory | What it exercises | Expected result |
| --- | --- | --- |
| `scratch-copy` | `COPY` of one file onto `scratch` | image id and digest |
| `build-args` | global `ARG`, `ENV`, `LABEL`, `WORKDIR`, relative `COPY` | pass `--build-arg GREETING=world` |
| `multi-stage` | named stages and `COPY --from` | default stage is `final`; `--target docs` builds the first stage; `--target missing` fails |
| `containerfile` | `Containerfile` with no `Dockerfile` | omit `-f` and let the CLI discover it |
| `dockerignore` | `COPY .` with an ignore file | context includes files the ignore list drops |
| `missing-copy` | `COPY` of a path that is not in the context | exit 5 |
| `unknown-instruction` | an instruction Buildah does not recognize | exit 5 |

`crates/oci-builder/tests/build_image.rs` builds this table when the engine is available. On macOS it runs `scratch-copy` when `guest/out` is present and virtualization is available, and skips the table otherwise.
