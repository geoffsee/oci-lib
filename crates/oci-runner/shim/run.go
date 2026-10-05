//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

/*
#include "ror_abi.h"
*/
import "C"

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func runContainer(req *C.ror_run_request) (int, *shimError) {
	rootfs := goString(req.rootfs)
	cwd := goString(req.cwd)
	hostname := goString(req.hostname)
	stateRoot := goString(req.state_root)
	argv := goStrings(req.argv, req.argv_count)
	env := goStrings(req.env, req.env_count)
	isolate := req.isolate_network != 0

	if rootfs == "" || !filepath.IsAbs(rootfs) {
		return 0, fail(errInvalid, "rootfs must be an absolute path", "")
	}
	info, err := os.Stat(rootfs)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fail(errNotFound, "rootfs not found", rootfs)
		}
		return 0, fail(errInvalid, "rootfs", err.Error())
	}
	if !info.IsDir() {
		return 0, fail(errInvalid, "rootfs is not a directory", rootfs)
	}
	if len(argv) == 0 || argv[0] == "" {
		return 0, fail(errInvalid, "command is empty", "")
	}
	if cwd == "" || !filepath.IsAbs(cwd) {
		return 0, fail(errInvalid, "cwd must be an absolute path", cwd)
	}
	if hostname == "" || len(hostname) > 64 {
		return 0, fail(errInvalid, "hostname must be 1 to 64 bytes", "")
	}

	if stateRoot == "" {
		stateRoot, err = defaultStateRoot()
		if err != nil {
			return 0, fail(errInternal, "state directory", err.Error())
		}
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return 0, fail(errInvalid, "state directory", err.Error())
	}

	isHostRoot := false
	if rootfs == "/" {
		isHostRoot = true
		hostRoot := filepath.Join(stateRoot, "host-rootfs")
		if err := os.MkdirAll(hostRoot, 0o755); err != nil {
			return 0, fail(errInternal, "create host rootfs mountpoint", err.Error())
		}
		if err := syscall.Mount("/", hostRoot, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			return 0, fail(errRun, "bind mount host root", err.Error())
		}
		defer func() {
			_ = syscall.Unmount(hostRoot, syscall.MNT_DETACH)
			_ = os.Remove(hostRoot)
		}()
		rootfs = hostRoot
	}

	spec := specconv.Example()
	spec.Root.Path = rootfs
	spec.Root.Readonly = false
	spec.Hostname = hostname
	spec.Process.Terminal = false
	spec.Process.Args = argv
	spec.Process.Env = env
	spec.Process.Cwd = cwd
	spec.Process.User = specs.User{UID: 0, GID: 0}

	rootless := os.Geteuid() != 0
	if rootless {
		specconv.ToRootless(spec)
	}
	spec.Linux.Namespaces = withNetwork(spec.Linux.Namespaces, isolate)
	if !isolate && !isHostRoot {
		if err := bindResolv(spec, rootfs); err != nil {
			return 0, fail(errRun, "resolv.conf", err.Error())
		}
	}
	if err := applySeccomp(spec); err != nil {
		return 0, fail(errRun, "seccomp profile", err.Error())
	}

	opts := &specconv.CreateOpts{
		CgroupName:      "oci-runner",
		Spec:            spec,
		RootlessEUID:    rootless,
		RootlessCgroups: rootless,
	}
	config, err := specconv.CreateLibcontainerConfig(opts)
	if err != nil {
		return 0, fail(errRun, "container config", err.Error())
	}
	var st syscall.Statfs_t
	if (syscall.Statfs("/", &st) == nil && st.Type == 0x858458f6) || isRootfs() {
		config.NoPivotRoot = true
	}
	if isolate {
		config.Networks = []*configs.Network{{
			Type:    "loopback",
			Address: "127.0.0.1/0",
			Gateway: "localhost",
		}}
	}

	id := fmt.Sprintf("run-%d-%d", os.Getpid(), time.Now().UnixNano())
	container, err := libcontainer.Create(stateRoot, id, config)
	if err != nil {
		return 0, fail(errRun, "create container", err.Error())
	}
	defer func() { _ = container.Destroy() }()

	process := &libcontainer.Process{
		Args: argv,
		Env:  env,
		Cwd:  cwd,
		Init: true,
	}
	var readers sync.WaitGroup
	if req.stdio_fn != nil {
		null, err := os.Open(os.DevNull)
		if err != nil {
			return 0, fail(errInternal, "open /dev/null", err.Error())
		}
		defer null.Close()
		process.Stdin = null
		if err := pipeStream(&readers, &process.Stdout, req.stdio_fn, req.stdio_user, streamStdout); err != nil {
			return 0, err
		}
		if err := pipeStream(&readers, &process.Stderr, req.stdio_fn, req.stdio_user, streamStderr); err != nil {
			closeWriters(process)
			readers.Wait()
			return 0, err
		}
	} else {
		process.Stdin = os.Stdin
		process.Stdout = os.Stdout
		process.Stderr = os.Stderr
	}

	if err := container.Run(process); err != nil {
		closeWriters(process)
		readers.Wait()
		return 0, fail(errRun, "start container", err.Error())
	}
	closeWriters(process)
	state, err := process.Wait()
	readers.Wait()
	if err != nil {
		return 0, fail(errRun, "wait", err.Error())
	}
	return exitCode(state), nil
}

func withNetwork(namespaces []specs.LinuxNamespace, isolate bool) []specs.LinuxNamespace {
	out := make([]specs.LinuxNamespace, 0, len(namespaces)+1)
	for _, ns := range namespaces {
		if ns.Type == specs.NetworkNamespace {
			continue
		}
		out = append(out, ns)
	}
	if isolate {
		out = append(out, specs.LinuxNamespace{Type: specs.NetworkNamespace})
	}
	return out
}

func bindResolv(spec *specs.Spec, rootfs string) error {
	source := "/etc/resolv.conf"
	if _, err := os.Stat(source); err != nil {
		return nil
	}
	target := filepath.Join(rootfs, "etc", "resolv.conf")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if fi, err := os.Lstat(target); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if _, err := os.Stat(target); err != nil && os.IsNotExist(err) {
			_ = os.Remove(target)
		}
	}
	if _, err := os.Stat(target); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.WriteFile(target, nil, 0o644); err != nil {
			return err
		}
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Source:      source,
		Destination: "/etc/resolv.conf",
		Type:        "bind",
		Options:     []string{"rbind", "ro"},
	})
	return nil
}

func pipeStream(readers *sync.WaitGroup, slot *io.Writer, fn C.ror_stdio_fn, user unsafe.Pointer, stream C.int32_t) *shimError {
	read, write, err := os.Pipe()
	if err != nil {
		return fail(errInternal, "stdio pipe", err.Error())
	}
	*slot = write
	readers.Add(1)
	go func() {
		defer readers.Done()
		defer read.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := read.Read(buf)
			if n > 0 {
				emitStdio(fn, user, stream, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return nil
}

func closeWriters(process *libcontainer.Process) {
	if file, ok := process.Stdout.(*os.File); ok && file != os.Stdout {
		_ = file.Close()
	}
	if file, ok := process.Stderr.(*os.File); ok && file != os.Stderr {
		_ = file.Close()
	}
}

func exitCode(state *os.ProcessState) int {
	if state == nil {
		return 1
	}
	code := state.ExitCode()
	if code >= 0 {
		return code
	}
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return 1
}

func defaultStateRoot() (string, error) {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "oci-runner"), nil
	}
	id := os.Getuid()
	if u, err := user.Current(); err == nil {
		if parsed, err := strconv.Atoi(u.Uid); err == nil {
			id = parsed
		}
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("oci-runner-%d", id)), nil
}

func isRootfs() bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "/" && (fields[0] == "rootfs" || fields[2] == "rootfs") {
			return true
		}
	}
	return false
}
