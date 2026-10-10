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
/// the graph root on an ext4 image, brings up NAT, then runs the engine agent.
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
# mkdir and rename. Keep the share, and mount an ext2 image from it at the
# path the engine was given. The run root is ephemeral.
mkdir -p /mnt/.host-root /mnt/root /mnt/runroot
if mount -t virtiofs root /mnt/.host-root 2>/dev/null; then
    img=/mnt/.host-root/rob-store.img
    if [ ! -s "$img" ]; then
        # Sparse 8 GiB. vfs stores a full copy of each layer, so 256 MiB
        # fills up on an ordinary base image.
        dd if=/dev/zero of="$img" bs=1M seek=8192 count=0
        mke2fs -F "$img" >/dev/null
    fi
    if ! mount -t ext4 "$img" /mnt/root 2>/dev/null; then
        mount -t ext2 "$img" /mnt/root
    fi
else
    mount -t tmpfs tmpfs /mnt/root
fi
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
        ifconfig "$interface" "$ip" netmask "$netmask" up
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
