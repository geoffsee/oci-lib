//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestResolveImageIdentityAndGroups(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"passwd": "worker:x:1000:1000::/:/bin/sh\n", "group": "worker:x:1000:\nimage:x:50000:worker\n"} {
		if err := os.WriteFile(filepath.Join(root, "etc", name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, selected := range []string{"worker", "1000:1000"} {
		for _, strict := range []bool{false, true} {
			got, err := opResolveUser(&opRequest{Rootfs: root, User: selected, Groups: []uint32{1234, 1000}, Strict: strict})
			if err != nil {
				t.Fatal(err)
			}
			actual := got.(specs.User)
			want := []uint32{1000, 1234, 50000}
			if strict {
				want = []uint32{1000, 1234}
			}
			if actual.UID != 1000 || actual.GID != 1000 || !reflect.DeepEqual(actual.AdditionalGids, want) {
				t.Fatalf("%s strict=%v: %+v", selected, strict, actual)
			}
		}
	}
	if _, err := opResolveUser(&opRequest{Rootfs: root, User: "missing"}); err == nil {
		t.Fatal("unknown account silently resolved")
	}
	if err := os.Remove(filepath.Join(root, "etc", "passwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "etc", "passwd")); err != nil {
		t.Fatal(err)
	}
	if _, err := opResolveUser(&opRequest{Rootfs: root, User: "root"}); err == nil {
		t.Fatal("passwd symlink escaped rootfs")
	}
}
