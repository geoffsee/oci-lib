//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/specconv"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Container lifecycle on libcontainer. Shapes mirror runc's create/start:
// libcontainer.Create lays down state, Start runs the init process, Wait
// reaps it. Handles live in a registry because start and wait are separate
// rok_calls; the state root also makes containers reloadable after a daemon
// restart via libcontainer.Load.

type handle struct {
	container *libcontainer.Container
	process   *libcontainer.Process
	stdin     io.WriteCloser
	pumps     sync.WaitGroup
	exitCode  int
	done      bool
}

var (
	handlesMu sync.Mutex
	handles   = map[string]*handle{}
)

func stateRoot(root string) string {
	if root == "" {
		return "/run/oci-cri/state"
	}
	// Callers pass either the store root (state lives in <root>/state) or,
	// when the request carries an explicit state_root, that path via
	// stateRootOf. This helper resolves the store-root form.
	return filepath.Join(root, "state")
}

func stateRootOf(req *opRequest) string {
	if req.StateRoot != "" {
		return req.StateRoot
	}
	return stateRoot(req.StoreRoot)
}

func specDir(root string) string {
	return filepath.Join(root, "specs")
}

func loadContainer(req *opRequest, id string) (*libcontainer.Container, error) {
	container, err := libcontainer.Load(stateRootOf(req), id)
	if err != nil {
		return nil, fail(codeNotFound, "container not found", err.Error())
	}
	return container, nil
}

func savedSpec(root, id string) (*specs.Spec, error) {
	data, err := os.ReadFile(filepath.Join(specDir(root), id+".json"))
	if err != nil {
		return nil, fail(codeInternal, "reading saved spec", err.Error())
	}
	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fail(codeInternal, "parsing saved spec", err.Error())
	}
	return &spec, nil
}

func getHandle(req *opRequest, id string) (*handle, error) {
	handlesMu.Lock()
	defer handlesMu.Unlock()
	if h, ok := handles[id]; ok {
		return h, nil
	}
	container, err := loadContainer(req, id)
	if err != nil {
		return nil, err
	}
	h := &handle{container: container, exitCode: -1}
	handles[id] = h
	return h, nil
}

func opCreate(req *opRequest) error {
	if req.ID == "" {
		return fail(codeInvalid, "container id is empty", "")
	}
	var spec specs.Spec
	if err := json.Unmarshal(req.Spec, &spec); err != nil {
		return fail(codeInvalid, "spec is not an OCI spec", err.Error())
	}
	if spec.Root == nil || spec.Root.Path == "" {
		return fail(codeInvalid, "spec has no root path", "")
	}
	if err := os.MkdirAll(stateRootOf(req), 0o700); err != nil {
		return fail(codeInternal, "state directory", err.Error())
	}
	if err := os.MkdirAll(specDir(req.StoreRoot), 0o700); err != nil {
		return fail(codeInternal, "spec directory", err.Error())
	}
	rootless := os.Geteuid() != 0
	if rootless {
		specconv.ToRootless(&spec)
	}
	if !rootless {
		if err := prepareCgroupRoot(); err != nil {
			return fail(codeRun, "prepare delegated cgroup", err.Error())
		}
	}
	opts := &specconv.CreateOpts{
		CgroupName:      req.ID,
		Spec:            &spec,
		RootlessEUID:    rootless,
		RootlessCgroups: rootless,
	}
	config, err := specconv.CreateLibcontainerConfig(opts)
	if err != nil {
		return fail(codeRun, "container config", err.Error())
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil && st.Type == 0x858458f6 {
		config.NoPivotRoot = true
	}
	container, err := libcontainer.Create(stateRootOf(req), req.ID, config)
	if err != nil {
		return fail(codeRun, "create container", err.Error())
	}
	specJSON, err := json.Marshal(&spec)
	if err != nil {
		return fail(codeInternal, "encoding spec", err.Error())
	}
	if err := os.WriteFile(filepath.Join(specDir(req.StoreRoot), req.ID+".json"), specJSON, 0o600); err != nil {
		_ = container.Destroy()
		return fail(codeInternal, "saving spec", err.Error())
	}
	handlesMu.Lock()
	handles[req.ID] = &handle{container: container, exitCode: -1}
	handlesMu.Unlock()
	return nil
}

func opStart(req *opRequest, hooks *ioHooks) error {
	h, err := getHandle(req, req.ID)
	if err != nil {
		return err
	}
	spec, err := savedSpec(req.StoreRoot, req.ID)
	if err != nil {
		return err
	}
	if spec.Process == nil {
		return fail(codeInvalid, "spec has no process", "")
	}
	process := &libcontainer.Process{
		Args:          spec.Process.Args,
		Env:           spec.Process.Env,
		Cwd:           spec.Process.Cwd,
		Init:          true,
		ConsoleWidth:  0,
		ConsoleHeight: 0,
	}
	if spec.Process.User.UID != 0 || spec.Process.User.GID != 0 {
		process.UID = int(spec.Process.User.UID)
		process.GID = int(spec.Process.User.GID)
	}
	for _, gid := range spec.Process.User.AdditionalGids {
		process.AdditionalGroups = append(process.AdditionalGroups, int(gid))
	}
	// stdin is a pipe so Attach can write to it later.
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		return fail(codeInternal, "stdin pipe", err.Error())
	}
	defer stdinRead.Close()
	started := false
	defer func() {
		if !started {
			_ = stdinWrite.Close()
			h.stdin = nil
		}
	}()
	process.Stdin = stdinRead
	h.stdin = stdinWrite
	if hooks != nil && hooks.emit != nil {
		emit := hooks.emit
		if err := pipeTo(&h.pumps, &process.Stdout, emit, 1); err != nil {
			return err
		}
		// Start duplicates these descriptors into the child. Keeping the
		// parent writers open prevents EOF and deadlocks opWait on pumps.
		defer process.Stdout.(*os.File).Close()
		if spec.Process.Terminal {
			process.Stderr = process.Stdout
		} else {
			if err := pipeTo(&h.pumps, &process.Stderr, emit, 2); err != nil {
				return err
			}
			defer process.Stderr.(*os.File).Close()
		}
	} else {
		process.Stdout = os.Stdout
		process.Stderr = os.Stderr
	}
	if err := h.container.Start(process); err != nil {
		_ = stdinRead.Close()
		return fail(codeRun, "start container", err.Error())
	}
	if err := h.container.Exec(); err != nil {
		return fail(codeRun, "exec container init", err.Error())
	}
	_ = stdinRead.Close()
	h.process = process
	started = true
	return nil
}

func opWait(req *opRequest) (any, error) {
	h, err := getHandle(req, req.ID)
	if err != nil {
		return nil, err
	}
	if h.done {
		return map[string]any{"exit_code": h.exitCode}, nil
	}
	code := -1
	if h.process != nil {
		state, err := h.process.Wait()
		// A nonzero exit (including SIGKILL) returns both state and ExitError.
		if err != nil && state == nil {
			return nil, fail(codeRun, "wait", err.Error())
		}
		code = exitCode(state)
	}
	h.pumps.Wait()
	h.exitCode = code
	h.done = true
	return map[string]any{"exit_code": code}, nil
}

func opKill(req *opRequest) error {
	h, err := getHandle(req, req.ID)
	if err != nil {
		return err
	}
	signal := syscall.Signal(req.Signal)
	if signal == 0 {
		signal = syscall.SIGTERM
	}
	if err := h.container.Signal(signal); err != nil {
		// Killing an already-stopped container is not an error for CRI.
		if status, serr := h.container.Status(); serr == nil && status == libcontainer.Stopped {
			return nil
		}
		return fail(codeRun, "signal container", err.Error())
	}
	return nil
}

func opDelete(req *opRequest) error {
	h, err := getHandle(req, req.ID)
	if err != nil {
		return nil // already gone
	}
	if status, serr := h.container.Status(); serr == nil && status != libcontainer.Stopped {
		_ = h.container.Signal(syscall.SIGKILL)
		if h.process != nil && !h.done {
			_, _ = h.process.Wait()
			h.done = true
		}
	}
	if h.stdin != nil {
		_ = h.stdin.Close()
	}
	if err := h.container.Destroy(); err != nil {
		return fail(codeRun, "destroy container", err.Error())
	}
	handlesMu.Lock()
	delete(handles, req.ID)
	handlesMu.Unlock()
	_ = os.Remove(filepath.Join(specDir(req.StoreRoot), req.ID+".json"))
	return nil
}

func opState(req *opRequest) (any, error) {
	container, err := loadContainer(req, req.ID)
	if err != nil {
		// Fall back to the in-memory handle (e.g. state root cleaned up).
		handlesMu.Lock()
		h, ok := handles[req.ID]
		handlesMu.Unlock()
		if !ok {
			return nil, err
		}
		container = h.container
	}
	status, err := container.Status()
	if err != nil {
		return nil, fail(codeInternal, "container status", err.Error())
	}
	pid := 0
	exit := -1
	if state, err := container.State(); err == nil && state.InitProcessPid > 0 {
		pid = state.InitProcessPid
	}
	handlesMu.Lock()
	if h, ok := handles[req.ID]; ok && h.done {
		exit = h.exitCode
	}
	handlesMu.Unlock()
	name := "stopped"
	switch status {
	case libcontainer.Running:
		name = "running"
	case libcontainer.Created:
		name = "created"
	case libcontainer.Paused:
		name = "paused"
	}
	return map[string]any{"status": name, "pid": pid, "exit_code": exit}, nil
}

func opStats(req *opRequest) (any, error) {
	container, err := loadContainer(req, req.ID)
	if err != nil {
		return nil, err
	}
	stats, err := container.Stats()
	if err != nil {
		return nil, fail(codeRun, "container stats", err.Error())
	}
	out := engineStats(stats)
	if spec, err := savedSpec(req.StoreRoot, req.ID); err == nil && spec.Root != nil {
		size, inodes := dirUsage(spec.Root.Path)
		out["writable_size"] = size
		out["inodes_used"] = inodes
	}
	return out, nil
}

// engineStats is the complete JSON contract consumed by Rust EngineStats.
func engineStats(stats *libcontainer.Stats) map[string]any {
	out := map[string]any{
		"cpu_total_ns":  uint64(0),
		"cpu_system_ns": uint64(0),
		"mem_usage":     uint64(0),
		"mem_limit":     uint64(1<<63 - 1),
		"mem_cache":     uint64(0),
		"mem_swap":      uint64(0),
		"writable_size": uint64(0),
		"inodes_used":   uint64(0),
	}
	if stats.CgroupStats != nil {
		out["cpu_total_ns"] = stats.CgroupStats.CpuStats.CpuUsage.TotalUsage
		out["cpu_system_ns"] = stats.CgroupStats.CpuStats.CpuUsage.UsageInKernelmode
		out["cpu_percpu_ns"] = stats.CgroupStats.CpuStats.CpuUsage.PercpuUsage
		out["mem_usage"] = stats.CgroupStats.MemoryStats.Usage.Usage
		if stats.CgroupStats.MemoryStats.Usage.Limit != 0 {
			out["mem_limit"] = stats.CgroupStats.MemoryStats.Usage.Limit
		}
		out["mem_cache"] = stats.CgroupStats.MemoryStats.Cache
		out["mem_swap"] = stats.CgroupStats.MemoryStats.SwapUsage.Usage
	}
	var rx, tx, rxErrors, txErrors uint64
	for _, iface := range stats.Interfaces {
		rx += iface.RxBytes
		tx += iface.TxBytes
		rxErrors += iface.RxErrors
		txErrors += iface.TxErrors
	}
	out["rx_bytes"] = rx
	out["tx_bytes"] = tx
	out["rx_errors"] = rxErrors
	out["tx_errors"] = txErrors
	return out
}

func dirUsage(root string) (uint64, uint64) {
	var size, inodes uint64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		inodes++
		if info.Mode().IsRegular() {
			size += uint64(info.Size())
		}
		return nil
	})
	return size, inodes
}

func opUpdate(req *opRequest) error {
	container, err := loadContainer(req, req.ID)
	if err != nil {
		return err
	}
	var resources specs.LinuxResources
	if len(req.Resources) > 0 {
		if err := json.Unmarshal(req.Resources, &resources); err != nil {
			return fail(codeInvalid, "resources", err.Error())
		}
	}
	config := container.Config()
	if config.Cgroups != nil && config.Cgroups.Resources != nil {
		target := config.Cgroups.Resources
		if resources.CPU != nil {
			if resources.CPU.Shares != nil {
				target.CpuShares = *resources.CPU.Shares
			}
			if resources.CPU.Quota != nil {
				target.CpuQuota = *resources.CPU.Quota
			}
			if resources.CPU.Period != nil {
				target.CpuPeriod = *resources.CPU.Period
			}
			if resources.CPU.Cpus != "" {
				target.CpusetCpus = resources.CPU.Cpus
			}
			if resources.CPU.Mems != "" {
				target.CpusetMems = resources.CPU.Mems
			}
		}
		if resources.Memory != nil && resources.Memory.Limit != nil {
			target.Memory = *resources.Memory.Limit
		}
	}
	if err := container.Set(config); err != nil {
		return fail(codeRun, "update resources", err.Error())
	}
	return nil
}

type callbackReader struct {
	read func(buf []byte) (int, error)
	buf  []byte
}

func (r *callbackReader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		chunk := make([]byte, 4096)
		n, err := r.read(chunk)
		if err != nil {
			return 0, io.EOF
		}
		if n == 0 {
			return 0, io.EOF
		}
		r.buf = chunk[:n]
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

type callbackWriter struct {
	emit   func(stream int32, data []byte)
	stream int32
}

func (w *callbackWriter) Write(p []byte) (int, error) {
	w.emit(w.stream, p)
	return len(p), nil
}

func opExec(req *opRequest, hooks *ioHooks) (any, error) {
	h, err := getHandle(req, req.ID)
	if err != nil {
		return nil, err
	}
	if len(req.Cmd) == 0 {
		return nil, fail(codeInvalid, "exec command is empty", "")
	}
	spec, _ := savedSpec(req.StoreRoot, req.ID)
	process := &libcontainer.Process{
		Args: req.Cmd,
		Init: false,
	}
	if spec != nil && spec.Process != nil {
		process.Env = spec.Process.Env
		process.Cwd = spec.Process.Cwd
		process.UID = int(spec.Process.User.UID)
		process.GID = int(spec.Process.User.GID)
	}
	if hooks != nil && hooks.readInput != nil {
		process.Stdin = &callbackReader{read: hooks.readInput}
	} else {
		process.Stdin = nil
	}
	if hooks != nil && hooks.emit != nil {
		process.Stdout = &callbackWriter{emit: hooks.emit, stream: 1}
		if req.TTY {
			process.Stderr = process.Stdout
		} else {
			process.Stderr = &callbackWriter{emit: hooks.emit, stream: 2}
		}
	}
	if err := h.container.Run(process); err != nil {
		return nil, fail(codeRun, "exec", err.Error())
	}
	state, err := process.Wait()
	if err != nil && state == nil {
		return nil, fail(codeRun, "exec wait", err.Error())
	}
	return map[string]any{"exit_code": exitCode(state)}, nil
}

func opWriteStdin(req *opRequest) error {
	h, err := getHandle(req, req.ID)
	if err != nil {
		return err
	}
	if h.stdin == nil {
		return fail(codeState, "container stdin is not open", "")
	}
	if req.Data == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		return fail(codeInvalid, "stdin data", err.Error())
	}
	if _, err := h.stdin.Write(data); err != nil {
		return fail(codeRun, "write stdin", err.Error())
	}
	return nil
}

func opResize(req *opRequest) error {
	// Piped (non-console) stdio has no winsize to set; terminal resize is a
	// no-op at this layer and reported as success so kubelet does not retry.
	_, err := getHandle(req, req.ID)
	return err
}

func opCheckpoint(req *opRequest) error {
	h, err := getHandle(req, req.ID)
	if err != nil {
		return err
	}
	if req.Image == "" {
		return fail(codeInvalid, "checkpoint location is empty", "")
	}
	if err := os.MkdirAll(req.Image, 0o755); err != nil {
		return fail(codeInternal, "checkpoint directory", err.Error())
	}
	opts := &libcontainer.CriuOpts{
		ImagesDirectory:   req.Image,
		WorkDirectory:     filepath.Join(req.Image, "work"),
		LeaveRunning:      false,
		TcpEstablished:    true,
		ShellJob:          false,
		FileLocks:         true,
		ManageCgroupsMode: "full",
	}
	if err := h.container.Checkpoint(opts); err != nil {
		return fail(codeRun, "checkpoint (needs CRIU)", err.Error())
	}
	return nil
}

func pipeTo(pumps *sync.WaitGroup, slot *io.Writer, emit func(stream int32, data []byte), stream int32) error {
	read, write, err := os.Pipe()
	if err != nil {
		return fail(codeInternal, "stdio pipe", err.Error())
	}
	*slot = write
	pumps.Add(1)
	go func() {
		defer pumps.Done()
		defer read.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := read.Read(buf)
			if n > 0 {
				emit(stream, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return nil
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
