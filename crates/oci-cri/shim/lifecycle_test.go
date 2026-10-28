//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/cgroups"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/types"
)

func TestEngineStatsContract(t *testing.T) {
	stats := &libcontainer.Stats{CgroupStats: &cgroups.Stats{}, Interfaces: []*types.NetworkInterface{
		{RxBytes: 10, TxBytes: 20, RxErrors: 1, TxErrors: 2},
		{RxBytes: 30, TxBytes: 40, RxErrors: 3, TxErrors: 4},
	}}
	stats.CgroupStats.CpuStats.CpuUsage.UsageInKernelmode = 123
	out := engineStats(stats)
	for key, want := range map[string]uint64{"rx_bytes": 40, "tx_bytes": 60, "rx_errors": 4, "tx_errors": 6, "cpu_system_ns": 123} {
		if out[key] != want {
			t.Errorf("%s = %v, want %d", key, out[key], want)
		}
	}
	for _, key := range []string{"cpu_total_ns", "cpu_system_ns", "mem_usage", "mem_limit", "mem_cache", "mem_swap", "writable_size", "inodes_used", "rx_bytes", "tx_bytes", "rx_errors", "tx_errors"} {
		if _, ok := engineStats(&libcontainer.Stats{})[key]; !ok {
			t.Errorf("missing required Rust field %s", key)
		}
	}
	if _, err := json.Marshal(out); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupRejectsSharedOrThreadedRootBeforeMutation(t *testing.T) {
	for _, tc := range []struct{ kind, procs, message string }{
		{"domain", "1\n42\n", "another process"},
		{"domain threaded", "42\n", "must be domain"},
		{"threaded", "42\n", "must be domain"},
	} {
		t.Run(tc.kind+tc.procs, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range map[string]string{"cgroup.type": tc.kind, "cgroup.procs": tc.procs, "cgroup.subtree_control": ""} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := prepareCgroupRootAt(root, "42"); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("unexpected error: %v", err)
			}
			entries, _ := os.ReadDir(root)
			if len(entries) != 3 {
				t.Fatal("rejected setup mutated cgroup layout")
			}
			data, _ := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
			if len(data) != 0 {
				t.Fatal("rejected setup enabled controllers")
			}
		})
	}
}
