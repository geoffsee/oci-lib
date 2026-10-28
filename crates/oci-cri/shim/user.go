//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/moby/sys/user"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func opResolveUser(req *opRequest) (any, error) {
	root, err := os.OpenRoot(req.Rootfs)
	if err != nil {
		return nil, fail(codeInvalid, "open user rootfs", err.Error())
	}
	defer root.Close()
	open := func(path string) (io.Reader, error) {
		f, err := root.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		// All resolution completes before the enclosing function returns.
		return f, nil
	}
	passwd, err := open("etc/passwd")
	if err != nil {
		return nil, fail(codeInvalid, "read image passwd", err.Error())
	}
	if passwd != nil {
		defer passwd.(*os.File).Close()
	}
	group, err := open("etc/group")
	if err != nil {
		return nil, fail(codeInvalid, "read image group", err.Error())
	}
	if group != nil {
		defer group.(*os.File).Close()
	}
	// Resolve membership independently of an explicitly supplied primary group.
	selected := strings.SplitN(req.User, ":", 2)
	account, err := user.GetExecUser(selected[0], nil, passwd, group)
	if err != nil {
		return nil, fail(codeInvalid, "resolve image user", err.Error())
	}
	if len(selected) == 2 {
		if passwd != nil {
			_, _ = passwd.(*os.File).Seek(0, io.SeekStart)
		}
		if group != nil {
			_, _ = group.(*os.File).Seek(0, io.SeekStart)
		}
		explicit, err := user.GetExecUser(req.User, nil, passwd, group)
		if err != nil {
			return nil, fail(codeInvalid, "resolve image group", err.Error())
		}
		account.Gid = explicit.Gid
	}
	groups := map[uint32]bool{uint32(account.Gid): true}
	for _, gid := range req.Groups {
		groups[gid] = true
	}
	if !req.Strict {
		for _, gid := range account.Sgids {
			groups[uint32(gid)] = true
		}
	}
	result := specs.User{UID: uint32(account.Uid), GID: uint32(account.Gid), AdditionalGids: make([]uint32, 0, len(groups))}
	for gid := range groups {
		result.AdditionalGids = append(result.AdditionalGids, gid)
	}
	sort.Slice(result.AdditionalGids, func(i, j int) bool { return result.AdditionalGids[i] < result.AdditionalGids[j] })
	return result, nil
}
