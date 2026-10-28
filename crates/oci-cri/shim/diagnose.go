//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func unixNano() int64 { return time.Now().UnixNano() }

func diagnoseHost() (string, error) {
	var lines []string
	blocked := false
	add := func(ok bool, text string) {
		if ok {
			lines = append(lines, "[ok] "+text)
		} else {
			blocked = true
			lines = append(lines, "[fail] "+text)
		}
	}
	if _, err := os.Stat("/proc/self/ns/net"); err == nil {
		add(true, "kernel namespaces are available")
	} else {
		add(false, "kernel namespaces are not available")
	}
	if _, err := os.Stat("/sys/fs/cgroup"); err == nil {
		add(true, "cgroup hierarchy is mounted")
	} else {
		add(false, "cgroup hierarchy is not mounted")
	}
	if os.Geteuid() == 0 {
		add(true, "running as root")
	} else {
		lines = append(lines, "[warn] not running as root; rootless mode will be used")
	}
	report := fmt.Sprintf("status: %s\n%s\n", map[bool]string{true: "blocked", false: "ready"}[blocked], strings.Join(lines, "\n"))
	if blocked {
		return report, fail(codePrereq, "host cannot run containers", report)
	}
	return report, nil
}
