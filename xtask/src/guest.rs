// SPDX-License-Identifier: Apache-2.0

//! Scripts placed in the guest initramfs. BusyBox runs them inside the VM.

/// PID 1 for the oci-runner guest. Mounts the rootfs share, brings up NAT,
/// then runs the engine agent.
pub const RUNNER_INIT: &str = r#"#!/bin/busybox sh
# PID 1 for the macOS Virtualization.framework guest.
# Mounts the rootfs virtiofs tag, brings up NAT, then runs the engine agent.

/bin/busybox --install -s /bin

export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mkdir -p /proc /sys /dev /etc /root /mnt /tmp /var/tmp /var/run /run
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm

printf '%s\n' 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd
printf '%s\n' 'root:x:0:' > /etc/group
printf '%s\n' 'passwd: files' 'group: files' > /etc/nsswitch.conf
printf '%s\n' 'hosts: files dns' >> /etc/nsswitch.conf

mkdir -p /mnt/rootfs
if ! mount -t virtiofs rootfs /mnt/rootfs; then
    echo "oci-runner: failed to mount virtiofs tag rootfs" >&2
fi

mkdir -p /sys/fs/cgroup
mount -t cgroup2 cgroup2 /sys/fs/cgroup || true

ip link set lo up 2>/dev/null || true
for iface in /sys/class/net/*; do
    name=${iface##*/}
    case "$name" in
        lo) continue ;;
    esac
    # sit0 and other kernel tunnels have no device and never answer DHCP.
    if [ ! -e "$iface/device" ]; then
        continue
    fi
    ip link set "$name" up 2>/dev/null || true
    udhcpc -i "$name" -q -n -t 5 -T 1 -s /udhcpc.script || true
done

# Stay PID 1 after the agent exits. Exiting here panics the kernel
# ("Attempted to kill init") while the host is still reading the console.
/oci-runner --engine-serve
while true; do
    sleep 3600
done
"#;

/// PID 1 for the oci-builder guest. Mounts the shares the host exported, puts
/// the graph root on an ext image, brings up NAT, then runs the engine agent.
///
/// The filesystem is the image file itself (no partition table). The format
/// comment in the script identifies ext2, mounted as ext4 when the kernel
/// accepts it. `resize2fs` is not in this guest, and enlarging the file
/// without `resize2fs` does not enlarge the filesystem. An existing nonempty
/// `rob-store.img` is left mounted unchanged: never shrink it, never rerun
/// `mke2fs` on it, and never delete it from the guest.
///
/// To recreate the store, work on a copy first: shut the VM down, copy the
/// image aside, delete `rob-store.img`, and let the next boot create a new
/// sparse 8GiB image.
pub const BUILDER_INIT: &str = r#"#!/bin/busybox sh
# PID 1 for the macOS Virtualization.framework guest.
# Mounts the virtiofs tags the host exported, brings up NAT, then runs the engine agent.

/bin/busybox --install -s /bin

export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mkdir -p /proc /sys /dev /etc /root /mnt /tmp /var/tmp /var/run /run
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm

printf '%s\n' 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd
printf '%s\n' 'root:x:0:' > /etc/group
printf '%s\n' 'passwd: files' 'group: files' > /etc/nsswitch.conf
printf '%s\n' 'hosts: files dns' >> /etc/nsswitch.conf

# Buildah opens a netavark backend while creating every build container,
# including a scratch COPY that never configures a network. The lookup only
# checks that the helper exists. A later RUN that needs a bridge will fail
# until a real netavark is installed.
mkdir -p /usr/libexec/podman /run/lock /run/containers/networks
printf '%s\n' '#!/bin/busybox sh' 'exit 0' > /usr/libexec/podman/netavark
chmod 755 /usr/libexec/podman/netavark

for tag in context policy registries auth; do
    mkdir -p "/mnt/$tag"
    mount -t virtiofs "$tag" "/mnt/$tag" 2>/dev/null || true
done

# The graph root cannot live directly on Apple virtiofs. containers/storage
# chowns layer directories to uid 0, and the host share then returns EPERM for
# mkdir and rename. Keep the share, and mount an ext image from it at the
# path the engine was given. The run root is ephemeral.
# Format: ext2, no partition table. Mounted as ext4 when the kernel accepts it.
mkdir -p /mnt/.host-root /mnt/root /mnt/runroot
root_mounted=0
if mount -t virtiofs root /mnt/.host-root 2>/dev/null; then
    img=/mnt/.host-root/rob-store.img
    if [ ! -s "$img" ]; then
        # Sparse 8 GiB. vfs stores a full copy of each layer, so 256 MiB
        # fills up on an ordinary base image.
        dd if=/dev/zero of="$img" bs=1M seek=8192 count=0
        mke2fs -F "$img" >/dev/null
    else
        # No resize2fs in this guest; rewriting a nonempty image would drop the store.
        echo "oci-builder: existing rob-store.img left unchanged; this guest does not grow it. Recreation: shut the VM down, copy the image aside, delete rob-store.img, and let the next boot create a new sparse 8GiB image." >&2
    fi
    if mount -t ext4 "$img" /mnt/root 2>/dev/null || mount -t ext2 "$img" /mnt/root; then
        root_mounted=1
    fi
elif mount -t tmpfs tmpfs /mnt/root; then
    root_mounted=1
fi
if [ "$root_mounted" != 1 ]; then
    echo "oci-builder: failed to mount /mnt/root; not setting TMPDIR" >&2
    exit 1
fi
# Buildah scratch space cannot live on Apple virtiofs or a RAM tmpfs.
mkdir -p /mnt/root/tmp
chmod 1777 /mnt/root/tmp
export TMPDIR=/mnt/root/tmp
export TMP=/mnt/root/tmp
export TEMP=/mnt/root/tmp
mount -t tmpfs tmpfs /mnt/runroot

ip link set lo up 2>/dev/null || true
for iface in /sys/class/net/*; do
    name=${iface##*/}
    case "$name" in
        lo) continue ;;
    esac
    # sit0 and other kernel tunnels have no device and never answer DHCP.
    if [ ! -e "$iface/device" ]; then
        continue
    fi
    ip link set "$name" up 2>/dev/null || true
    udhcpc -i "$name" -q -n -t 5 -T 1 -s /udhcpc.script || true
done

# Stay PID 1 after the agent exits. Exiting here panics the kernel
# ("Attempted to kill init") while the host is still reading the console.
/oci-builder --engine-serve
sync
umount /mnt/root 2>/dev/null || true
while true; do
    sleep 3600
done
"#;

/// The udhcpc hook both guests use to apply a DHCP lease. Installed as
/// /udhcpc.script, the path the init scripts pass to `udhcpc -s`.
pub const UDHCPC_SCRIPT: &str = r#"#!/bin/busybox sh
# udhcpc calls this with bound, renew, or deconfig.
# BusyBox exports the dotted netmask as `subnet`.
case "$1" in
    bound|renew)
        netmask=${subnet:-255.255.255.0}
        # Apple VZ NAT can reset large TLS handshakes at an Ethernet MTU of
        # 1500. Smaller TCP segments avoid that path limit while preserving
        # certificate verification and Go's default post-quantum TLS groups.
        # 1280 also accommodates IPv6's minimum link MTU.
        ifconfig "$interface" "$ip" netmask "$netmask" mtu 1280 up
        if [ -n "$router" ]; then
            route add default gw "$router" 2>/dev/null || true
        fi
        if [ -n "$dns" ]; then
            : > /etc/resolv.conf
            for server in $dns; do
                printf 'nameserver %s\n' "$server" >> /etc/resolv.conf
            done
        fi
        ;;
esac
"#;
