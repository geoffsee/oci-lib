//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

/*
#include "rob_abi.h"
*/
import "C"

import (
	"fmt"
	"strings"
	"time"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.podman.io/buildah"
	"go.podman.io/image/v5/manifest"
	"go.podman.io/image/v5/transports"
	"go.podman.io/image/v5/transports/alltransports"
	"go.podman.io/image/v5/types"
	"go.podman.io/storage/pkg/archive"
)

//export rob_push
func rob_push(req *C.rob_push_request, out *C.rob_result, errOut *C.rob_error) C.int32_t {
	if req == nil {
		return fail(errOut, errInvalid, "push request is NULL", "")
	}
	if code := ensureStarted(errOut); code != 0 {
		return code
	}
	opMu.Lock()
	defer opMu.Unlock()
	if state.store == nil {
		return fail(errOut, errState, "store is not open", "call rob_init before rob_push")
	}
	clearResult(out)

	image := goString(req.image)
	destination := goString(req.destination)
	if image == "" || destination == "" {
		return fail(errOut, errInvalid, "image and destination are required", "")
	}
	manifestType, formatErr := pushFormat(goString(req.format))
	if formatErr != nil {
		return fail(errOut, errInvalid, formatErr.Error(), "")
	}
	dest, destSpec, parseErr := parseDest(destination)
	if parseErr != nil {
		return fail(errOut, errInvalid, parseErr.Error(), "")
	}

	sys := cloneSystem(state.sys)
	if req.insecure != 0 {
		applyInsecure(sys)
	}
	user := goString(req.username)
	pass := goString(req.password)
	if user != "" || pass != "" {
		sys.DockerAuthConfig = &types.DockerAuthConfig{
			Username: user,
			Password: pass,
		}
	}

	var sink *logSink
	if req.log_fn != nil {
		sink = &logSink{fn: req.log_fn, user: req.log_user}
	}
	restore, _, _, report, _ := bindLogs(sink, false)
	defer restore()

	ctx, reg := contextFor(req.cancel_token)
	defer releaseCancel(reg)
	if ctx.Err() != nil {
		return fail(errOut, errCancelled, "operation cancelled", "")
	}

	ref, dig, pushErr := buildah.Push(ctx, image, dest, buildah.PushOptions{
		Compression:         archive.Gzip,
		SignaturePolicyPath: state.policy,
		ReportWriter:        report,
		Store:               state.store,
		SystemContext:       sys,
		ManifestType:        manifestType,
		RemoveSignatures:    false,
		MaxRetries:          3,
		RetryDelay:          time.Second,
	})
	if pushErr != nil {
		return failErr(errOut, pushErr, errPush)
	}

	id := image
	if looked, _, lookErr := imageRecord(image); lookErr == nil && looked != "" {
		id = looked
	}
	refName := destSpec
	if ref != nil {
		refName = ref.String()
	}
	digest := ""
	if dig != "" {
		digest = dig.String()
	}
	if out != nil {
		setBuffer(&out.image_id, id)
		setBuffer(&out.digest, digest)
		setBuffer(&out.reference, refName)
	}
	return 0
}

func cloneSystem(base *types.SystemContext) *types.SystemContext {
	if base == nil {
		return &types.SystemContext{}
	}
	cp := *base
	return &cp
}

func pushFormat(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", nil
	case "oci":
		return imgspecv1.MediaTypeImageManifest, nil
	case "docker", "v2s2":
		return manifest.DockerV2Schema2MediaType, nil
	case "v2s1":
		return manifest.DockerV2Schema1SignedMediaType, nil
	default:
		return "", fmt.Errorf("unknown push format %q", s)
	}
}

func parseDest(destSpec string) (types.ImageReference, string, error) {
	dest, err := alltransports.ParseImageName(destSpec)
	if err == nil {
		return dest, destSpec, nil
	}
	if strings.Contains(destSpec, "://") {
		return nil, destSpec, err
	}
	transport, _, hasSep := strings.Cut(destSpec, ":")
	if hasSep {
		if t := transports.Get(transport); t != nil {
			return nil, destSpec, err
		}
	}
	prefixed := "docker://" + destSpec
	dest2, err2 := alltransports.ParseImageName(prefixed)
	if err2 != nil {
		return nil, destSpec, err
	}
	return dest2, prefixed, nil
}
