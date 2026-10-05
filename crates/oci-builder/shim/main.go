//go:build linux

// SPDX-License-Identifier: Apache-2.0

// Command robshim is the Buildah c-archive linked into the Rust crate.
// main is required by -buildmode=c-archive and is not called.
package main

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include "rob_abi.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/sirupsen/logrus"
	"go.podman.io/buildah"
	"go.podman.io/common/libimage"
	"go.podman.io/image/v5/types"
	"go.podman.io/storage"
	"go.podman.io/storage/pkg/unshare"
)

const (
	errOK          = 0
	errInvalid     = 1
	errCancelled   = 2
	errNotFound    = 3
	errPrereq      = 4
	errBuild       = 5
	errPush        = 6
	errTag         = 7
	errUnsupported = 8
	errInternal    = 9
	errState       = 10

	logProgress = 0
	logInfo     = 1
	logWarn     = 2
	logError    = 3
)

func main() {}

type engineState struct {
	store  storage.Store
	sys    *types.SystemContext
	policy string
	level  logrus.Level
}

var (
	opMu  sync.Mutex
	state engineState

	startOnce   sync.Once
	startCode   int
	startMsg    string
	startDetail string

	cancelMu  sync.Mutex
	cancels          = map[uint64]*cancelReg{}
	nextToken uint64 = 1

	versionOnce sync.Once
	versionPtr  *C.char
)

type cancelReg struct {
	mu        sync.Mutex
	cancelled bool
	cancel    context.CancelFunc
}

type logSink struct {
	fn   C.rob_log_fn
	user unsafe.Pointer
	mu   sync.Mutex
}

type chunkWriter struct {
	sink  *logSink
	level C.int32_t
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	if w == nil || w.sink == nil || len(p) == 0 {
		return len(p), nil
	}
	cleaned := strings.ReplaceAll(string(p), "\x00", "")
	w.sink.emit(w.level, cleaned)
	return len(p), nil
}

type logrusHook struct {
	sink *logSink
}

func (h *logrusHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h *logrusHook) Fire(entry *logrus.Entry) error {
	msg, err := entry.String()
	if err != nil {
		return err
	}
	h.sink.emit(logrusLevel(entry.Level), msg)
	return nil
}

func logrusLevel(level logrus.Level) C.int32_t {
	switch level {
	case logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel:
		return logError
	case logrus.WarnLevel:
		return logWarn
	case logrus.InfoLevel:
		return logInfo
	default:
		return logProgress
	}
}

func goString(p *C.char) string {
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

func goStrings(p **C.char, n C.size_t) []string {
	if p == nil || n == 0 {
		return nil
	}
	raw := unsafe.Slice(p, int(n))
	out := make([]string, int(n))
	for i, item := range raw {
		out[i] = goString(item)
	}
	return out
}

func setBuffer(b *C.rob_buffer, s string) {
	if b == nil {
		return
	}
	s = strings.ReplaceAll(s, "\x00", "")
	if s == "" {
		b.data = nil
		b.len = 0
		return
	}
	b.data = C.CString(s)
	b.len = C.size_t(len(s))
}

func fail(dst *C.rob_error, code int, message, detail string) C.int32_t {
	if dst != nil {
		dst.code = C.int32_t(code)
		setBuffer(&dst.message, message)
		setBuffer(&dst.detail, detail)
	}
	return C.int32_t(code)
}

func failErr(dst *C.rob_error, err error, fallback int) C.int32_t {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return fail(dst, errCancelled, "operation cancelled", err.Error())
	}
	if libimage.ErrorIsImageUnknown(err) || errors.Is(err, storage.ErrImageUnknown) {
		return fail(dst, errNotFound, "image not found", err.Error())
	}
	return fail(dst, fallback, err.Error(), "")
}

//export rob_startup
func rob_startup(err *C.rob_error) C.int32_t {
	return ensureStarted(err)
}

func ensureStarted(dst *C.rob_error) C.int32_t {
	startOnce.Do(func() {
		if buildah.InitReexec() {
			os.Exit(0)
		}
		logrus.SetOutput(os.Stderr)
		logrus.SetLevel(logrus.WarnLevel)
		report, blocked := collectFindings()
		if blocked {
			startCode = errPrereq
			startMsg = "host is missing a kernel, user namespace, or storage prerequisite"
			startDetail = report
			return
		}
		unshare.MaybeReexecUsingUserNamespace(false)
		startCode = errOK
	})
	if startCode != errOK {
		return fail(dst, startCode, startMsg, startDetail)
	}
	return 0
}

//export rob_init
func rob_init(cfg *C.rob_config, err *C.rob_error) C.int32_t {
	if cfg == nil {
		return fail(err, errInvalid, "config is NULL", "")
	}
	if code := ensureStarted(err); code != 0 {
		return code
	}
	opMu.Lock()
	defer opMu.Unlock()
	if state.store != nil {
		return fail(err, errState, "store is already open", "call shutdown before opening another store")
	}
	level, levelErr := parseLevel(goString(cfg.log_level))
	if levelErr != nil {
		return fail(err, errInvalid, levelErr.Error(), "")
	}
	opts, optErr := storage.DefaultStoreOptions()
	if optErr != nil {
		return fail(err, errPrereq, optErr.Error(), collectReport())
	}
	if root := goString(cfg.storage_root); root != "" {
		opts.GraphRoot = root
	}
	if run := goString(cfg.run_root); run != "" {
		opts.RunRoot = run
	}
	if driver := goString(cfg.storage_driver); driver != "" {
		opts.GraphDriverName = driver
		opts.GraphDriverOptions = append([]string(nil), goStrings(cfg.storage_opts, cfg.storage_opt_count)...)
	} else if cfg.storage_opt_count > 0 {
		opts.GraphDriverOptions = append([]string(nil), goStrings(cfg.storage_opts, cfg.storage_opt_count)...)
	}
	store, storeErr := storage.GetStore(opts)
	if storeErr != nil {
		return fail(err, errPrereq, storeErr.Error(), collectReport())
	}
	sys := &types.SystemContext{}
	policy := goString(cfg.signature_policy)
	if policy != "" {
		sys.SignaturePolicyPath = policy
	}
	if auth := goString(cfg.auth_file); auth != "" {
		sys.AuthFilePath = auth
	}
	if reg := goString(cfg.registries_conf); reg != "" {
		sys.SystemRegistriesConfPath = reg
	}
	if cfg.insecure != 0 {
		applyInsecure(sys)
	}
	state.store = store
	state.sys = sys
	state.policy = policy
	state.level = level
	return 0
}

func parseLevel(s string) (logrus.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "warn", "warning":
		return logrus.WarnLevel, nil
	case "info":
		return logrus.InfoLevel, nil
	case "debug":
		return logrus.DebugLevel, nil
	case "error":
		return logrus.ErrorLevel, nil
	case "trace":
		return logrus.TraceLevel, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", s)
	}
}

func applyInsecure(sys *types.SystemContext) {
	sys.DockerInsecureSkipTLSVerify = types.NewOptionalBool(true)
	sys.OCIInsecureSkipTLSVerify = true
	sys.DockerDaemonInsecureSkipTLSVerify = true
}

func collectReport() string {
	report, _ := collectFindings()
	return report
}

//export rob_shutdown
func rob_shutdown(err *C.rob_error) C.int32_t {
	opMu.Lock()
	defer opMu.Unlock()
	if state.store == nil {
		return 0
	}
	_, storeErr := state.store.Shutdown(false)
	state.store = nil
	state.sys = nil
	state.policy = ""
	if storeErr != nil {
		return fail(err, errInternal, storeErr.Error(), "")
	}
	return 0
}

//export rob_diagnose
func rob_diagnose(out *C.rob_buffer, err *C.rob_error) C.int32_t {
	opMu.Lock()
	defer opMu.Unlock()
	report, blocked := collectFindings()
	if out != nil {
		setBuffer(out, report)
	}
	if blocked {
		return fail(err, errPrereq, "host is missing a kernel, user namespace, or storage prerequisite", report)
	}
	return 0
}

//export rob_cancel_new
func rob_cancel_new() C.uint64_t {
	cancelMu.Lock()
	defer cancelMu.Unlock()
	id := nextToken
	nextToken++
	if nextToken == 0 {
		nextToken = 1
	}
	cancels[id] = &cancelReg{}
	return C.uint64_t(id)
}

//export rob_cancel
func rob_cancel(token C.uint64_t) {
	if token == 0 {
		return
	}
	cancelMu.Lock()
	reg := cancels[uint64(token)]
	cancelMu.Unlock()
	if reg == nil {
		return
	}
	reg.mu.Lock()
	reg.cancelled = true
	cancel := reg.cancel
	reg.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

//export rob_cancel_free
func rob_cancel_free(token C.uint64_t) {
	if token == 0 {
		return
	}
	cancelMu.Lock()
	delete(cancels, uint64(token))
	cancelMu.Unlock()
}

func contextFor(token C.uint64_t) (context.Context, *cancelReg) {
	if token == 0 {
		return context.Background(), nil
	}
	cancelMu.Lock()
	reg := cancels[uint64(token)]
	cancelMu.Unlock()
	if reg == nil {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, nil
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	if reg.cancelled {
		cancel()
		return ctx, reg
	}
	reg.cancel = cancel
	return ctx, reg
}

func releaseCancel(reg *cancelReg) {
	if reg == nil {
		return
	}
	reg.mu.Lock()
	cancel := reg.cancel
	reg.cancel = nil
	reg.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func bindLogs(sink *logSink, quiet bool) (restore func(), out, errw, report io.Writer, logf func(string, ...any)) {
	lg := logrus.StandardLogger()
	prevOut := lg.Out
	prevLevel := lg.GetLevel()
	prevHooks := lg.ReplaceHooks(make(logrus.LevelHooks))
	lg.SetLevel(state.level)
	if sink != nil {
		lg.SetOutput(io.Discard)
		lg.AddHook(&logrusHook{sink: sink})
		errw = &chunkWriter{sink: sink, level: logError}
		if !quiet {
			out = &chunkWriter{sink: sink, level: logInfo}
			report = &chunkWriter{sink: sink, level: logProgress}
		}
		logf = func(format string, args ...any) {
			sink.emit(logInfo, fmt.Sprintf(format, args...))
		}
	} else {
		lg.SetOutput(os.Stderr)
		errw = os.Stderr
		if !quiet {
			out = os.Stderr
			report = os.Stderr
		}
	}
	restore = func() {
		lg.ReplaceHooks(prevHooks)
		lg.SetOutput(prevOut)
		lg.SetLevel(prevLevel)
	}
	return restore, out, errw, report, logf
}

func clearResult(out *C.rob_result) {
	if out == nil {
		return
	}
	out.image_id = C.rob_buffer{}
	out.digest = C.rob_buffer{}
	out.reference = C.rob_buffer{}
}

func imageRecord(name string) (id, digest string, err error) {
	rt, err := libimage.RuntimeFromStore(state.store, &libimage.RuntimeOptions{SystemContext: state.sys})
	if err != nil {
		return "", "", err
	}
	img, _, err := rt.LookupImage(name, &libimage.LookupImageOptions{ManifestList: true})
	if err != nil {
		return "", "", err
	}
	id = img.ID()
	if d := img.Digest(); d != "" {
		digest = d.String()
	}
	return id, digest, nil
}

//export rob_buffer_free
func rob_buffer_free(buf *C.rob_buffer) {
	if buf == nil {
		return
	}
	if buf.data != nil {
		C.free(unsafe.Pointer(buf.data))
		buf.data = nil
	}
	buf.len = 0
}

//export rob_error_free
func rob_error_free(err *C.rob_error) {
	if err == nil {
		return
	}
	rob_buffer_free(&err.message)
	rob_buffer_free(&err.detail)
	err.code = 0
}

//export rob_result_free
func rob_result_free(res *C.rob_result) {
	if res == nil {
		return
	}
	rob_buffer_free(&res.image_id)
	rob_buffer_free(&res.digest)
	rob_buffer_free(&res.reference)
}

//export rob_buildah_version
func rob_buildah_version() *C.char {
	versionOnce.Do(func() {
		versionPtr = C.CString(buildahVersion())
	})
	return versionPtr
}
