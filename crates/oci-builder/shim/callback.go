//go:build linux

// SPDX-License-Identifier: Apache-2.0

package main

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include "rob_abi.h"
#include <stdlib.h>

static void rob_call_log(rob_log_fn fn, void *user, int32_t level, const char *data, size_t len) {
	if (fn != 0) {
		fn(user, level, data, len);
	}
}
*/
import "C"

import (
	"strings"
	"unsafe"
)

// emit is in this file so cgo can see rob_call_log. A file that uses //export
// cannot define that helper in its preamble.
func (s *logSink) emit(level C.int32_t, msg string) {
	if s == nil || s.fn == nil || msg == "" {
		return
	}
	msg = strings.ReplaceAll(msg, "\x00", "")
	if msg == "" {
		return
	}
	cstr := C.CString(msg)
	defer C.free(unsafe.Pointer(cstr))
	s.mu.Lock()
	defer s.mu.Unlock()
	C.rob_call_log(s.fn, s.user, level, cstr, C.size_t(len(msg)))
}
