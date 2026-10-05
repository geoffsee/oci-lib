//go:build linux && !seccomp

// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/opencontainers/runtime-spec/specs-go"

func applySeccomp(spec *specs.Spec) error {
	if spec.Linux != nil {
		spec.Linux.Seccomp = nil
	}
	return nil
}
