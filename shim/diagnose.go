//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"strings"

	"github.com/opencontainers/runc/libcontainer/seccomp"
)

func diagnoseHost() (string, *shimError) {
	var lines []string
	blocked := false
	failLine := func(text string) {
		blocked = true
		lines = append(lines, "[fail] "+text)
	}
	okLine := func(text string) { lines = append(lines, "[ok] "+text) }
	warnLine := func(text string) { lines = append(lines, "[warn] "+text) }

	for _, ns := range []string{"user", "mnt", "pid", "uts", "ipc"} {
		path := "/proc/self/ns/" + ns
		if _, err := os.Stat(path); err != nil {
			failLine(path + " is missing")
		} else {
			okLine(path)
		}
	}

	if os.Geteuid() != 0 {
		if value, ok := sysctl("/proc/sys/kernel/unprivileged_userns_clone"); ok && value == "0" {
			failLine("kernel.unprivileged_userns_clone=0")
		} else if ok {
			okLine("kernel.unprivileged_userns_clone=" + value)
		}
		if value, ok := sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); ok && value == "1" {
			failLine("kernel.apparmor_restrict_unprivileged_userns=1")
		} else if ok {
			okLine("kernel.apparmor_restrict_unprivileged_userns=" + value)
		}
		if value, ok := sysctl("/proc/sys/user/max_user_namespaces"); ok && value == "0" {
			failLine("user.max_user_namespaces=0")
		} else if ok {
			okLine("user.max_user_namespaces=" + value)
		}
		if look("newuidmap") {
			okLine("newuidmap")
		} else {
			failLine("newuidmap is not on PATH")
		}
		if look("newgidmap") {
			okLine("newgidmap")
		} else {
			failLine("newgidmap is not on PATH")
		}
	} else {
		okLine("running as root")
	}

	if seccomp.Enabled {
		okLine("libseccomp is linked")
	} else {
		warnLine("built without libseccomp; containers run with no seccomp profile")
	}

	if cgroupMounted() {
		okLine("cgroup filesystem is mounted")
	} else {
		warnLine("cgroup filesystem is not mounted")
	}

	status := "ready"
	message := "host can run containers"
	var diagErr *shimError
	if blocked {
		status = "blocked"
		message = "host cannot run containers"
		diagErr = fail(errPrereq, message, "")
	}
	report := "status: " + status + "\n" + strings.Join(lines, "\n") + "\n"
	if diagErr != nil {
		diagErr.detail = report
	}
	return report, diagErr
}

func sysctl(path string) (string, bool) {
	text, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(text)), true
}

func look(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func cgroupMounted() bool {
	text, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(text), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[4] == "/sys/fs/cgroup" {
			return true
		}
		// mountinfo: mountpoint is field 4, fstype follows the "-" separator.
		for i := 6; i+1 < len(fields); i++ {
			if fields[i] == "-" && (fields[i+1] == "cgroup" || fields[i+1] == "cgroup2") {
				return true
			}
		}
	}
	return false
}
