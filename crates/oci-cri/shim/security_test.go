//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"go.podman.io/common/pkg/seccomp"
)

func TestSecurityProfilesFailClosed(t *testing.T) {
	spec := &specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{}}, Linux: &specs.Linux{}, Annotations: map[string]string{"io.oci-cri.seccomp": "runtime/default"}}
	err := applySecurity(spec)
	if !seccomp.IsEnabled() {
		if err == nil {
			t.Fatal("seccomp request succeeded without support")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if spec.Linux.Seccomp == nil || spec.Linux.Seccomp.DefaultAction == specs.ActAllow {
		t.Fatal("missing restrictive default filter")
	}
	for _, body := range []string{"{", "{}"} {
		path := filepath.Join(t.TempDir(), "profile.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		spec.Annotations["io.oci-cri.seccomp"] = path
		if err := applySecurity(spec); err == nil {
			t.Fatalf("accepted invalid profile %q", body)
		}
	}
	spec.Annotations["io.oci-cri.seccomp"] = "/does/not/exist.json"
	if err := applySecurity(spec); err == nil {
		t.Fatal("accepted missing profile")
	}
	spec.Annotations["io.oci-cri.privileged"] = "true"
	if err := applySecurity(spec); err != nil {
		t.Fatal(err)
	}
	if spec.Linux.Seccomp != nil {
		t.Fatal("privileged container retained seccomp")
	}
}
