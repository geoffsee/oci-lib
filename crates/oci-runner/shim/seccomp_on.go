//go:build linux && seccomp

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/moby/profiles/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// runc spec's example config has no seccomp section. The profile installed
// here is the Moby default, which is the filter Docker applies, compiled by
// libseccomp through libcontainer.
func applySeccomp(spec *specs.Spec) error {
	profile, err := seccomp.GetDefaultProfile(spec)
	if err != nil {
		return err
	}
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	spec.Linux.Seccomp = profile
	return nil
}
