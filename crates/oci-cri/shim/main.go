//go:build linux

// SPDX-License-Identifier: Apache-2.0

// Command rokshim is the oci-cri engine c-archive linked into the Rust
// crate. One Go runtime holds libcontainer and containers/image+storage.
// Every engine operation is a JSON request/response through rok_call (see
// shim/include/rok_abi.h and src/engine.rs for the op vocabulary).
package main

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include "rok_abi.h"
#include <stdlib.h>

static void rok_call_stdio(rok_stdio_fn fn, void *user, int32_t stream, const char *data, size_t len) {
	if (fn != NULL && data != NULL && len > 0) {
		fn(user, stream, data, len);
	}
}

static intptr_t rok_call_input(rok_input_fn fn, void *user, char *buf, size_t cap) {
	if (fn == NULL) {
		return -1;
	}
	return fn(user, buf, cap);
}
*/
import "C"

import (
	"encoding/json"
	"os"
	"strconv"
	"unsafe"

	_ "github.com/opencontainers/cgroups/devices"
	"github.com/opencontainers/runc/libcontainer"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
)

const (
	errInvalid     = int(C.ROK_ERR_INVALID)
	errNotFound    = int(C.ROK_ERR_NOT_FOUND)
	errPrereq      = int(C.ROK_ERR_PREREQUISITE)
	errRun         = int(C.ROK_ERR_RUN)
	errUnsupported = int(C.ROK_ERR_UNSUPPORTED)
	errInternal    = int(C.ROK_ERR_INTERNAL)
	errState       = int(C.ROK_ERR_STATE)

	streamStdout = int32(C.ROK_STDOUT)
	streamStderr = int32(C.ROK_STDERR)
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

//export rok_startup
func rok_startup(_ *C.rok_error) C.int32_t {
	return C.ROK_OK
}

//export rok_call
func rok_call(request *C.char, stdioFn C.rok_stdio_fn, stdioUser unsafe.Pointer, inputFn C.rok_input_fn, inputUser unsafe.Pointer, out *C.rok_buffer, errOut *C.rok_error) C.int32_t {
	if request == nil {
		return setErr(errOut, errInvalid, "request is null", "")
	}
	hooks := &ioHooks{}
	if stdioFn != nil {
		fn, user := stdioFn, stdioUser
		hooks.emit = func(stream int32, data []byte) {
			if len(data) == 0 {
				return
			}
			C.rok_call_stdio(fn, user, C.int32_t(stream), (*C.char)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
		}
	}
	if inputFn != nil {
		fn, user := inputFn, inputUser
		hooks.readInput = func(buf []byte) (int, error) {
			if len(buf) == 0 {
				return 0, nil
			}
			n := C.rok_call_input(fn, user, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
			if n < 0 {
				return 0, errInput
			}
			return int(n), nil
		}
	}
	var req opRequest
	if err := json.Unmarshal([]byte(C.GoString(request)), &req); err != nil {
		return setErr(errOut, errInvalid, "request is not JSON", err.Error())
	}
	response, shimErr := dispatch(&req, hooks)
	if shimErr != nil {
		return setGoErr(errOut, shimErr)
	}
	if out != nil {
		setCStringBuf(out, response)
	}
	return C.ROK_OK
}

//export rok_diagnose
func rok_diagnose(out *C.rok_buffer, errOut *C.rok_error) C.int32_t {
	report, diagErr := diagnoseHost()
	if out != nil {
		setCStringBuf(out, report)
	}
	if diagErr != nil {
		return setGoErr(errOut, diagErr)
	}
	return C.ROK_OK
}

//export rok_buffer_free
func rok_buffer_free(buf *C.rok_buffer) {
	if buf == nil {
		return
	}
	if buf.data != nil {
		C.free(unsafe.Pointer(buf.data))
		buf.data = nil
	}
	buf.len = 0
}

//export rok_error_free
func rok_error_free(err *C.rok_error) {
	if err == nil {
		return
	}
	rok_buffer_free(&err.message)
	rok_buffer_free(&err.detail)
	err.code = 0
}

func setGoErr(dst *C.rok_error, err error) C.int32_t {
	if se, ok := err.(*shimError); ok {
		return setErr(dst, se.code, se.message, se.detail)
	}
	return setErr(dst, errInternal, err.Error(), "")
}

func setErr(dst *C.rok_error, code int, msg, detail string) C.int32_t {
	c := C.int32_t(code)
	if dst == nil {
		return c
	}
	dst.code = c
	setCStringBuf(&dst.message, msg)
	setCStringBuf(&dst.detail, detail)
	return c
}

func setCStringBuf(buf *C.rok_buffer, text string) {
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
