//go:build linux

// SPDX-License-Identifier: Apache-2.0

// Command rorshim is the libcontainer c-archive linked into the Rust crate.
package main

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include "ror_abi.h"
#include <stdlib.h>

static void ror_call_stdio(ror_stdio_fn fn, void *user, int32_t stream, const char *data, size_t len) {
	if (fn != NULL && data != NULL && len > 0) {
		fn(user, stream, data, len);
	}
}
*/
import "C"

import (
	"os"
	"strconv"
	"unsafe"

	_ "github.com/opencontainers/cgroups/devices"
	"github.com/opencontainers/runc/libcontainer"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
)

const (
	errOK          = int(C.ROR_OK)
	errInvalid     = int(C.ROR_ERR_INVALID)
	errNotFound    = int(C.ROR_ERR_NOT_FOUND)
	errPrereq      = int(C.ROR_ERR_PREREQUISITE)
	errRun         = int(C.ROR_ERR_RUN)
	errUnsupported = int(C.ROR_ERR_UNSUPPORTED)
	errInternal    = int(C.ROR_ERR_INTERNAL)
	errState       = int(C.ROR_ERR_STATE)

	streamStdout = C.ROR_STDOUT
	streamStderr = C.ROR_STDERR
)

func main() {}

func init() {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		if os.Getenv("_LIBCONTAINER_INITPIPE") == "" {
			if syncPipe := os.Getenv("_LIBCONTAINER_SYNCPIPE"); syncPipe != "" {
				if fd, err := strconv.Atoi(syncPipe); err == nil && fd > 0 {
					_ = os.Setenv("_LIBCONTAINER_INITPIPE", strconv.Itoa(fd-1))
				}
			}
		}
		// Does not return. The re-exec child never reaches Rust main.
		libcontainer.Init()
	}
}

//export ror_startup
func ror_startup(_ *C.ror_error) C.int32_t {
	return C.ROR_OK
}

//export ror_run
func ror_run(req *C.ror_run_request, exitCode *C.int32_t, err *C.ror_error) C.int32_t {
	if exitCode != nil {
		*exitCode = 0
	}
	if req == nil {
		return setErr(err, errInvalid, "run request is null", "")
	}
	code, runErr := runContainer(req)
	if exitCode != nil {
		*exitCode = C.int32_t(code)
	}
	if runErr != nil {
		return setGoErr(err, runErr)
	}
	return C.ROR_OK
}

//export ror_diagnose
func ror_diagnose(out *C.ror_buffer, err *C.ror_error) C.int32_t {
	report, diagErr := diagnoseHost()
	if out != nil {
		setCStringBuf(out, report)
	}
	if diagErr != nil {
		return setGoErr(err, diagErr)
	}
	return C.ROR_OK
}

//export ror_buffer_free
func ror_buffer_free(buf *C.ror_buffer) {
	if buf == nil {
		return
	}
	if buf.data != nil {
		C.free(unsafe.Pointer(buf.data))
		buf.data = nil
	}
	buf.len = 0
}

//export ror_error_free
func ror_error_free(err *C.ror_error) {
	if err == nil {
		return
	}
	ror_buffer_free(&err.message)
	ror_buffer_free(&err.detail)
	err.code = 0
}

type shimError struct {
	code    int
	message string
	detail  string
}

func (e *shimError) Error() string { return e.message }

func fail(code int, message, detail string) *shimError {
	return &shimError{code: code, message: message, detail: detail}
}

func emitStdio(fn C.ror_stdio_fn, user unsafe.Pointer, stream C.int32_t, data []byte) {
	if fn == nil || len(data) == 0 {
		return
	}
	C.ror_call_stdio(fn, user, stream, (*C.char)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
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

func setGoErr(dst *C.ror_error, err error) C.int32_t {
	if se, ok := err.(*shimError); ok {
		return setErr(dst, se.code, se.message, se.detail)
	}
	return setErr(dst, errInternal, err.Error(), "")
}

func setErr(dst *C.ror_error, code int, msg, detail string) C.int32_t {
	c := C.int32_t(code)
	if dst == nil {
		return c
	}
	dst.code = c
	setCStringBuf(&dst.message, msg)
	setCStringBuf(&dst.detail, detail)
	return c
}

func setCStringBuf(buf *C.ror_buffer, text string) {
	if buf == nil {
		return
	}
	if text == "" {
		buf.data = nil
		buf.len = 0
		return
	}
	cstr := C.CString(text)
	if cstr == nil {
		buf.data = nil
		buf.len = 0
		return
	}
	buf.data = cstr
	buf.len = C.size_t(len(text))
}
