//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/moby/sys/capability"
	"go.podman.io/storage/pkg/unshare"
)

type finding struct {
	kind string
	text string
}

func collectFindings() (string, bool) {
	var items []finding
	add := func(kind, text string) {
		items = append(items, finding{kind: kind, text: text})
	}

	euid := os.Geteuid()
	rootlessUID := unshare.GetRootlessUID()
	add("ok", fmt.Sprintf("euid=%d rootless_uid=%d", euid, rootlessUID))

	if _, err := user.Current(); err != nil && !os.IsNotExist(err) {
		add("fail", "cannot identify the current user ("+err.Error()+"). /etc/passwd must resolve this uid before Buildah can start.")
	}

	switch {
	case euid == 0 && rootlessUID > 0:
		add("ok", "already inside a rootless user namespace")
	case !needsUserNS():
		add("ok", "running as root with CAP_SYS_ADMIN; a user namespace is not required")
	default:
		addUserNSFindings(add)
	}

	if hasFilesystem("overlay") {
		add("ok", "overlay filesystem is available")
	} else if _, ok := look("fuse-overlayfs"); ok {
		add("ok", "fuse-overlayfs is available for rootless overlay")
	} else {
		add("warn", "neither the overlay filesystem nor fuse-overlayfs is available. Use storage driver vfs, or install fuse-overlayfs.")
	}

	if policyFound() {
		add("ok", "signature policy found")
	} else {
		add("warn", "no signature policy at /etc/containers/policy.json or ~/.config/containers/policy.json. Pulls fail closed without one. Pass signature_policy or install containers-policy.")
	}

	_, hasRunc := look("runc")
	_, hasCrun := look("crun")
	if hasRunc || hasCrun {
		add("ok", "OCI runtime found on PATH")
	} else {
		add("warn", "neither runc nor crun is on PATH. RUN with oci or rootless isolation needs one. chroot isolation and scratch/COPY builds do not.")
	}

	blocked := false
	var b strings.Builder
	for _, item := range items {
		if item.kind == "fail" {
			blocked = true
			break
		}
	}
	status := "ready"
	if blocked {
		status = "blocked"
	}
	fmt.Fprintf(&b, "status: %s\n", status)
	for _, item := range items {
		fmt.Fprintf(&b, "[%s] %s\n", item.kind, item.text)
	}
	return b.String(), blocked
}

func needsUserNS() bool {
	if os.Geteuid() == 0 && unshare.GetRootlessUID() > 0 {
		return false
	}
	if os.Geteuid() != 0 {
		return true
	}
	ok, err := unshare.HasCapSysAdmin()
	return err != nil || !ok
}

func addUserNSFindings(add func(string, string)) {
	if _, err := os.Stat("/proc/self/ns/user"); err != nil {
		add("fail", "user namespaces are unavailable ("+err.Error()+"). This kernel cannot run rootless Buildah.")
	} else {
		add("ok", "/proc/self/ns/user is present")
	}
	if v, ok := readSysctl("user.max_user_namespaces"); ok && v == "0" {
		add("fail", "user.max_user_namespaces is 0. Raise it, for example: sysctl user.max_user_namespaces=15000")
	}
	if v, ok := readSysctl("kernel.unprivileged_userns_clone"); ok && v == "0" {
		add("fail", "kernel.unprivileged_userns_clone is 0. Set it to 1 to allow rootless containers.")
	}
	if v, ok := readSysctl("kernel.apparmor_restrict_unprivileged_userns"); ok && v == "1" {
		add("fail", "kernel.apparmor_restrict_unprivileged_userns is 1, which blocks rootless user namespaces. Set it to 0: sysctl kernel.apparmor_restrict_unprivileged_userns=0")
	}
	checkHelper(add, "newuidmap", capability.CAP_SETUID, "cap_setuid")
	checkHelper(add, "newgidmap", capability.CAP_SETGID, "cap_setgid")
	checkSubIDs(add)
}

func checkHelper(add func(string, string), name string, cap capability.Cap, capName string) {
	path, ok := look(name)
	if !ok {
		for _, dir := range []string{"/usr/bin", "/bin", "/usr/local/bin"} {
			cand := dir + "/" + name
			info, err := os.Stat(cand)
			if err == nil && !info.IsDir() {
				path = cand
				ok = true
				break
			}
		}
	}
	if !ok {
		add("fail", name+" was not found. Install the uidmap package (newuidmap and newgidmap).")
		return
	}
	good, err := unshare.IsSetID(path, os.ModeSetuid, cap)
	if err != nil {
		add("fail", fmt.Sprintf("%s at %s could not be checked: %s", name, path, err.Error()))
		return
	}
	if !good {
		add("fail", fmt.Sprintf("%s at %s is not setuid and lacks %s. Install uidmap and restore the setuid bit or file capability.", name, path, capName))
		return
	}
	add("ok", name+" is usable at "+path)
}

func checkSubIDs(add func(string, string)) {
	current, err := user.Current()
	if err != nil {
		if os.IsNotExist(err) {
			add("fail", "the current uid is not in the user database, so /etc/subuid cannot be selected. Add a passwd entry for this uid.")
		}
		return
	}
	uidmap, gidmap, err := unshare.GetSubIDMappings(current.Username, current.Username)
	if err != nil {
		add("fail", "cannot read subordinate ID ranges: "+err.Error())
		return
	}
	if len(uidmap) == 0 {
		add("fail", fmt.Sprintf("no subordinate UID range for %q in /etc/subuid. Add a line such as %s:100000:65536", current.Username, current.Username))
	} else {
		add("ok", fmt.Sprintf("subordinate UID range found for %s", current.Username))
	}
	if len(gidmap) == 0 {
		add("fail", fmt.Sprintf("no subordinate GID range for %q in /etc/subgid. Add a line such as %s:100000:65536", current.Username, current.Username))
	} else {
		add("ok", fmt.Sprintf("subordinate GID range found for %s", current.Username))
	}
}

func readSysctl(key string) (string, bool) {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func hasFilesystem(name string) bool {
	b, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[len(fields)-1] == name {
			return true
		}
	}
	return false
}

func look(name string) (string, bool) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return path, true
}

func policyFound() bool {
	candidates := []string{"/etc/containers/policy.json"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, home+"/.config/containers/policy.json")
	}
	for _, path := range candidates {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
