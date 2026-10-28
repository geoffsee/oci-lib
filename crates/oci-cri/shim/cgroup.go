//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/opencontainers/cgroups"
)

var cgroupSetupMu sync.Mutex

// libcontainer enables controllers at every ancestor of a workload. A populated
// cgroup namespace root would become threaded, breaking cgroup.kill and memory
// accounting. Move only ourselves to a leaf before enabling domain controllers.
func prepareCgroupRoot() error {
	if !cgroups.IsCgroup2UnifiedMode() {
		return nil
	}
	cgroupSetupMu.Lock()
	defer cgroupSetupMu.Unlock()
	return prepareCgroupRootAt("/sys/fs/cgroup", strconv.Itoa(os.Getpid()))
}

func prepareCgroupRootAt(root, pid string) error {
	typ, err := os.ReadFile(filepath.Join(root, "cgroup.type"))
	if os.IsNotExist(err) {
		// The actual (non-namespaced) hierarchy root is exempt from the
		// no-internal-process rule and has no cgroup.type file.
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(typ)) != "domain" {
		return fmt.Errorf("cgroup root must be domain, got %q; start in a fresh delegated cgroup", strings.TrimSpace(string(typ)))
	}
	procs, err := os.ReadFile(filepath.Join(root, "cgroup.procs"))
	if err != nil {
		return err
	}
	for _, occupant := range strings.Fields(string(procs)) {
		if occupant != pid {
			return fmt.Errorf("cgroup root contains another process (%s); provide an empty delegated cgroup or run oci-cri as its sole process", occupant)
		}
	}
	if len(strings.Fields(string(procs))) != 0 {
		leaf := filepath.Join(root, "oci-cri-runtime-"+pid)
		if err := os.Mkdir(leaf, 0o755); err != nil && !os.IsExist(err) {
			return err
		}
		if err := os.WriteFile(filepath.Join(leaf, "cgroup.procs"), []byte(pid), 0o644); err != nil {
			return fmt.Errorf("move runtime into cgroup leaf: %w", err)
		}
	}
	controllers, err := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	if err != nil {
		return err
	}
	var enable []string
	for _, controller := range strings.Fields(string(controllers)) {
		enable = append(enable, "+"+controller)
	}
	if len(enable) == 0 {
		return nil
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte(strings.Join(enable, " ")), 0o644); err != nil {
		return fmt.Errorf("enable delegated cgroup controllers: %w", err)
	}
	return nil
}
