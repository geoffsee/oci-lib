//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

/*
#include "rob_abi.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"go.podman.io/buildah/define"
	"go.podman.io/buildah/imagebuildah"
	"go.podman.io/buildah/pkg/parse"
	"go.podman.io/common/libimage"
	"go.podman.io/image/v5/docker/reference"
)

func buildahVersion() string { return define.Version }

//export rob_build
func rob_build(req *C.rob_build_request, out *C.rob_result, errOut *C.rob_error) C.int32_t {
	if req == nil {
		return fail(errOut, errInvalid, "build request is NULL", "")
	}
	if code := ensureStarted(errOut); code != 0 {
		return code
	}
	opMu.Lock()
	defer opMu.Unlock()
	if state.store == nil {
		return fail(errOut, errState, "store is not open", "call rob_init before rob_build")
	}
	clearResult(out)

	dockerfile := goString(req.dockerfile)
	contextDir := goString(req.context_dir)
	if dockerfile == "" {
		return fail(errOut, errInvalid, "dockerfile path is empty", "")
	}
	if contextDir == "" {
		return fail(errOut, errInvalid, "context directory is empty", "")
	}
	keys := goStrings(req.build_arg_keys, req.build_arg_count)
	vals := goStrings(req.build_arg_vals, req.build_arg_count)
	if len(keys) != len(vals) {
		return fail(errOut, errInvalid, "build-arg key and value counts differ", "")
	}
	args := make(map[string]string, len(keys))
	for i := range keys {
		if keys[i] == "" {
			return fail(errOut, errInvalid, "build-arg key is empty", "")
		}
		args[keys[i]] = vals[i]
	}
	labels := goStrings(req.labels, req.label_count)
	for _, label := range labels {
		if !strings.Contains(label, "=") {
			return fail(errOut, errInvalid, fmt.Sprintf("label %q is not key=value", label), "")
		}
	}

	isolation, isoErr := parse.IsolationOption(goString(req.isolation))
	if isoErr != nil {
		return fail(errOut, errInvalid, isoErr.Error(), "")
	}
	pull, pullErr := pullPolicy(goString(req.pull))
	if pullErr != nil {
		return fail(errOut, errInvalid, pullErr.Error(), "")
	}
	format, formatErr := buildFormat(goString(req.format))
	if formatErr != nil {
		return fail(errOut, errInvalid, formatErr.Error(), "")
	}
	layers, layerErr := layerFlag(int32(req.layers))
	if layerErr != nil {
		return fail(errOut, errInvalid, layerErr.Error(), "")
	}

	quiet := req.quiet != 0
	var sink *logSink
	if req.log_fn != nil {
		sink = &logSink{fn: req.log_fn, user: req.log_user}
	}
	restore, stdout, stderr, report, logf := bindLogs(sink, quiet)
	defer restore()

	options := define.BuildOptions{
		ContextDirectory:        contextDir,
		PullPolicy:              pull,
		Quiet:                   quiet,
		Isolation:               isolation,
		Args:                    args,
		Output:                  goString(req.tag),
		Out:                     stdout,
		Err:                     stderr,
		Log:                     logf,
		SignaturePolicyPath:     state.policy,
		ReportWriter:            report,
		OutputFormat:            format,
		SystemContext:           state.sys,
		CommonBuildOpts:         &define.CommonBuildOptions{},
		Target:                  goString(req.target),
		Labels:                  labels,
		Layers:                  layers,
		NoCache:                 req.no_cache != 0,
		Squash:                  req.squash != 0,
		RemoveIntermediateCtrs:  true,
		ForceRmIntermediateCtrs: true,
		MaxPullPushRetries:      3,
		PullPushRetryDelay:      time.Second,
	}
	osName := goString(req.os_name)
	arch := goString(req.arch)
	variant := goString(req.variant)
	if osName != "" || arch != "" || variant != "" {
		if osName == "" {
			osName = runtime.GOOS
		}
		if arch == "" {
			arch = runtime.GOARCH
		}
		options.Platforms = []struct{ OS, Arch, Variant string }{{
			OS: osName, Arch: arch, Variant: variant,
		}}
	}

	ctx, reg := contextFor(req.cancel_token)
	defer releaseCancel(reg)
	if ctx.Err() != nil {
		return fail(errOut, errCancelled, "operation cancelled", "")
	}

	id, ref, buildErr := imagebuildah.BuildDockerfiles(ctx, state.store, options, dockerfile)
	if buildErr != nil {
		return failErr(errOut, buildErr, errBuild)
	}
	refName, digest := canonicalParts(ref)
	if digest == "" && id != "" {
		if _, lookedUp, lookErr := imageRecord(id); lookErr == nil {
			digest = lookedUp
		}
	}
	if refName == "" {
		refName = goString(req.tag)
	}
	if out != nil {
		setBuffer(&out.image_id, id)
		setBuffer(&out.digest, digest)
		setBuffer(&out.reference, refName)
	}
	return 0
}

func canonicalParts(ref reference.Canonical) (name, digest string) {
	if ref == nil {
		return "", ""
	}
	name = ref.String()
	if d := ref.Digest(); d != "" {
		digest = d.String()
	}
	return name, digest
}

func pullPolicy(s string) (define.PullPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "missing", "ifmissing", "notpresent":
		return define.PullIfMissing, nil
	case "always", "true":
		return define.PullAlways, nil
	case "never", "false":
		return define.PullNever, nil
	case "ifnewer", "newer":
		return define.PullIfNewer, nil
	default:
		return 0, fmt.Errorf("unknown pull policy %q", s)
	}
}

func buildFormat(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "oci":
		return define.OCIv1ImageManifest, nil
	case "docker", "v2s2":
		return define.Dockerv2ImageManifest, nil
	default:
		return "", fmt.Errorf("unknown image format %q", s)
	}
}

func layerFlag(v int32) (bool, error) {
	switch v {
	case -1, 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, fmt.Errorf("invalid layers value %d", v)
	}
}

//export rob_tag
func rob_tag(image, newName *C.char, errOut *C.rob_error) C.int32_t {
	if code := ensureStarted(errOut); code != 0 {
		return code
	}
	opMu.Lock()
	defer opMu.Unlock()
	if state.store == nil {
		return fail(errOut, errState, "store is not open", "call rob_init before rob_tag")
	}
	src := goString(image)
	dst := goString(newName)
	if src == "" || dst == "" {
		return fail(errOut, errInvalid, "image and new name are required", "")
	}
	rt, err := libimage.RuntimeFromStore(state.store, &libimage.RuntimeOptions{SystemContext: state.sys})
	if err != nil {
		return failErr(errOut, err, errTag)
	}
	img, _, err := rt.LookupImage(src, &libimage.LookupImageOptions{ManifestList: true})
	if err != nil {
		return failErr(errOut, err, errTag)
	}
	if err := img.Tag(dst); err != nil {
		return failErr(errOut, err, errTag)
	}
	return 0
}
