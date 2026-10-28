//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/moby/sys/devices"
	runtimeAppArmor "github.com/opencontainers/runc/libcontainer/apparmor"
	"go.podman.io/common/pkg/apparmor"
	"os"
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"go.podman.io/common/pkg/capabilities"
	"go.podman.io/common/pkg/seccomp"
)

// Apply runtime-owned policy selections before libcontainer translates the spec.
// The resulting OCI spec is persisted so exec uses the same security policy.
func applySecurity(spec *specs.Spec) error {
	if spec.Process == nil || spec.Linux == nil {
		return fail(codeInvalid, "security policy requires process and linux spec", "")
	}
	if spec.Annotations["io.oci-cri.privileged"] == "true" {
		caps, err := capabilities.BoundingSet()
		if err != nil {
			return fail(codeRun, "privileged capabilities", err.Error())
		}
		spec.Process.Capabilities = &specs.LinuxCapabilities{Bounding: caps, Effective: caps, Permitted: caps}
		spec.Process.ApparmorProfile = ""
		spec.Linux.Seccomp = nil
		spec.Linux.MaskedPaths = nil
		spec.Linux.ReadonlyPaths = nil
		if spec.Linux.Resources == nil {
			spec.Linux.Resources = &specs.LinuxResources{}
		}
		spec.Linux.Resources.Devices = []specs.LinuxDeviceCgroup{{Allow: true, Access: "rwm"}}
		hostDevices, err := devices.HostDevices()
		if err != nil {
			return fail(codeRun, "privileged devices", err.Error())
		}
		spec.Linux.Devices = nil
		for _, device := range hostDevices {
			mode, uid, gid := device.FileMode, device.Uid, device.Gid
			spec.Linux.Devices = append(spec.Linux.Devices, specs.LinuxDevice{Path: device.Path, Type: string(device.Type), Major: device.Major, Minor: device.Minor, FileMode: &mode, UID: &uid, GID: &gid})
		}
		for i := range spec.Mounts {
			if spec.Mounts[i].Type == "sysfs" || spec.Mounts[i].Type == "proc" {
				for j, option := range spec.Mounts[i].Options {
					if option == "ro" {
						spec.Mounts[i].Options[j] = "rw"
					}
				}
			}
		}
		return nil
	}
	if spec.Process.ApparmorProfile == "unconfined" && !runtimeAppArmor.IsEnabled() {
		// On hosts without AppArmor there is no kernel profile to transition.
		spec.Process.ApparmorProfile = ""
	}
	if profile := spec.Process.ApparmorProfile; profile != "" && profile != "unconfined" {
		if !apparmor.IsEnabled() {
			return fail(codeUnsupported, "AppArmor is unavailable", "requested profile was not applied")
		}
		if profile == "runtime/default" {
			profile = ""
		}
		loaded, err := apparmor.CheckProfileAndLoadDefault(profile)
		if err != nil {
			return fail(codeInvalid, "load AppArmor profile", err.Error())
		}
		spec.Process.ApparmorProfile = loaded
	}
	selection := spec.Annotations["io.oci-cri.seccomp"]
	if selection == "" {
		return nil
	}
	if !seccomp.IsEnabled() {
		return fail(codeUnsupported, "seccomp is unavailable", "requested profile was not applied")
	}
	var profile *specs.LinuxSeccomp
	var err error
	if selection == "runtime/default" {
		profile, err = seccomp.GetDefaultProfile(spec)
	} else {
		if !filepath.IsAbs(selection) {
			return fail(codeInvalid, "seccomp profile path must be absolute", "")
		}
		var body []byte
		body, err = os.ReadFile(selection)
		if err == nil {
			profile, err = seccomp.LoadProfileFromBytes(body, spec)
		}
	}
	if err != nil {
		return fail(codeInvalid, "load seccomp profile", err.Error())
	}
	if profile == nil || profile.DefaultAction == "" {
		return fail(codeInvalid, "empty seccomp profile", "requested profile must define a policy")
	}
	spec.Linux.Seccomp = profile
	return nil
}
