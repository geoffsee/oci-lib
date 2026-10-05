#!/bin/sh
# Build the Linux guest image the macOS host boots.
# Run this on Linux, on the same architecture as the Mac (arm64 for Apple Silicon).
# Writes guest/out/vmlinuz and guest/out/initramfs. Those files are not committed.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

if [ "$(uname -s)" != "Linux" ]; then
    echo "guest/build.sh runs on Linux. It produces the kernel and initramfs a Mac boots." >&2
    exit 1
fi

case "$(uname -m)" in
    aarch64|arm64)
        kernel_name=kernel-arm64
        kernel_sha=a122ce7a69a77408eeef9423afd9f6915828ba74a767e3e1eace635f913e02c4
        ;;
    x86_64)
        kernel_name=kernel-x86_64
        kernel_sha=04f18c7f3a9bc6a26c601b472a7b95fd5e69f3cbbdc06622f731d7529aecf165
        ;;
    *)
        echo "unsupported architecture $(uname -m)" >&2
        exit 1
        ;;
esac

busybox_sha=b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314
kernel_url="https://github.com/arcboxlabs/kernel/releases/download/v0.0.25/${kernel_name}"
busybox_url="https://busybox.net/downloads/busybox-1.36.1.tar.bz2"

cache="$root/guest/cache"
out="$root/guest/out"
mkdir -p "$cache" "$out"

# musl-gcc does not search the glibc header tree, so linux/kd.h and mtd/mtd-user.h
# are invisible until those directories are linked into the musl include root.
link_musl_kernel_headers() {
    arch=$(uname -m)
    dest=/usr/include/${arch}-linux-musl
    if [ ! -d "$dest" ]; then
        echo "musl-gcc is installed but $dest is missing; install musl-dev" >&2
        exit 1
    fi
    link_one() {
        name=$1
        src=$2
        if [ -e "$dest/$name" ]; then
            return
        fi
        if [ ! -d "$src" ]; then
            echo "missing kernel headers at $src; install linux-libc-dev" >&2
            exit 1
        fi
        if [ -w "$dest" ]; then
            ln -s "$src" "$dest/$name"
        else
            sudo ln -s "$src" "$dest/$name"
        fi
    }
    link_one linux /usr/include/linux
    link_one asm-generic /usr/include/asm-generic
    link_one mtd /usr/include/mtd
    link_one asm "/usr/include/${arch}-linux-gnu/asm"
}

fetch() {
    url=$1
    dest=$2
    sha=$3
    if [ -f "$dest" ]; then
        got=$(sha256sum "$dest" | awk '{print $1}')
        if [ "$got" = "$sha" ]; then
            return
        fi
        rm -f "$dest"
    fi
    echo "fetching $url" >&2
    curl -fsSL -o "$dest.partial" "$url"
    got=$(sha256sum "$dest.partial" | awk '{print $1}')
    if [ "$got" != "$sha" ]; then
        echo "checksum mismatch for $dest: got $got want $sha" >&2
        rm -f "$dest.partial"
        exit 1
    fi
    mv "$dest.partial" "$dest"
}

fetch "$kernel_url" "$cache/$kernel_name" "$kernel_sha"
cp "$cache/$kernel_name" "$out/vmlinuz"

if [ ! -x "$cache/busybox" ]; then
    fetch "$busybox_url" "$cache/busybox-1.36.1.tar.bz2" "$busybox_sha"
    rm -rf "$cache/busybox-1.36.1"
    tar -xjf "$cache/busybox-1.36.1.tar.bz2" -C "$cache"
    (
        cd "$cache/busybox-1.36.1"
        make defconfig
        sed -i 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
        if ! grep -q '^CONFIG_STATIC=y$' .config; then
            printf '%s\n' 'CONFIG_STATIC=y' >> .config
        fi
        # busybox 1.36.1's tc applet uses CBQ netlink structs that
        # linux-libc-dev on Ubuntu 24.04 no longer ships. The guest does not
        # configure traffic control.
        sed -i 's/^CONFIG_TC=y/# CONFIG_TC is not set/' .config
        jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
        if command -v musl-gcc >/dev/null 2>&1; then
            link_musl_kernel_headers
            make -j"$jobs" CC=musl-gcc
        else
            echo "musl-gcc was not found; linking busybox statically against the system libc." >&2
            echo "Install musl-tools if that link fails." >&2
            make -j"$jobs"
        fi
    )
    cp "$cache/busybox-1.36.1/busybox" "$cache/busybox"
    chmod 755 "$cache/busybox"
fi

echo "building oci-builder without seccomp or apparmor" >&2
ROB_DISABLE_OPTIONAL_LIBS=1 cargo build --release --locked -p oci-builder
bin="$root/target/release/oci-builder"

stage=$(mktemp -d)
cleanup() {
    rm -rf "$stage"
}
trap cleanup EXIT

mkdir -p "$stage/bin"
cp "$cache/busybox" "$stage/bin/busybox"
chmod 755 "$stage/bin/busybox"
cp "$root/guest/init" "$stage/init"
cp "$root/guest/udhcpc.script" "$stage/udhcpc.script"
chmod 755 "$stage/init" "$stage/udhcpc.script"
cp "$bin" "$stage/oci-builder"
chmod 755 "$stage/oci-builder"

copy_lib() {
    src=$1
    case "$src" in
        /*) ;;
        *) return ;;
    esac
    if [ ! -e "$src" ]; then
        echo "missing shared library $src" >&2
        exit 1
    fi
    # ldd often names a symlink (/lib/ld-linux-*.so.1 -> aarch64-linux-gnu/...).
    # cp -a would keep that link and leave the target out of the initramfs.
    real=$(readlink -f "$src")
    dest_real="$stage$real"
    mkdir -p "$(dirname "$dest_real")"
    if [ ! -e "$dest_real" ]; then
        cp -a "$real" "$dest_real"
    fi
    if [ "$src" != "$real" ]; then
        dest="$stage$src"
        mkdir -p "$(dirname "$dest")"
        if [ ! -e "$dest" ] && [ ! -L "$dest" ]; then
            ln -s "$real" "$dest"
        fi
    fi
}

ldd_list=$(mktemp)
ldd "$bin" > "$ldd_list"
while read -r line; do
    case "$line" in
        *"=> not found"*|*"not found"*)
            echo "oci-builder is missing a library: $line" >&2
            exit 1
            ;;
    esac
    path=$(printf '%s\n' "$line" | sed -n 's/.*=>[[:space:]]*\(\/[^ ]*\).*/\1/p')
    if [ -z "$path" ]; then
        path=$(printf '%s\n' "$line" | awk '{print $1}')
    fi
    copy_lib "$path"
done < "$ldd_list"
rm -f "$ldd_list"

libc_path=$(ldd "$bin" | sed -n 's/.*libc\.so[^ ]* => \([^ ]*\).*/\1/p')
if [ -n "$libc_path" ]; then
    libc_dir=$(dirname "$libc_path")
    for nss in "$libc_dir"/libnss_files.so*; do
        if [ -e "$nss" ]; then
            copy_lib "$nss"
        fi
    done
fi

mkdir -p "$out"
(cd "$stage" && find . | cpio -o -H newc) | gzip -9 > "$out/initramfs"
echo "wrote $out/vmlinuz and $out/initramfs" >&2
