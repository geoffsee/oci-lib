/* SPDX-License-Identifier: Apache-2.0 */
/* Non-Linux stand-in for the engine c-archive. Same ABI, no engine. */

#include "rok.h"

#include <stdlib.h>
#include <string.h>

static void set_buf(rok_buffer *buf, const char *text) {
	size_t n;
	char *copy;
	if (buf == NULL) {
		return;
	}
	if (text == NULL) {
		text = "";
	}
	n = strlen(text);
	if (n == 0) {
		buf->data = NULL;
		buf->len = 0;
		return;
	}
	copy = (char *)malloc(n + 1);
	if (copy == NULL) {
		buf->data = NULL;
		buf->len = 0;
		return;
	}
	memcpy(copy, text, n + 1);
	buf->data = copy;
	buf->len = n;
}

/* build.rs sets this on macOS builds with the `vm` feature turned off. */
#ifndef ROK_STUB_DETAIL
#define ROK_STUB_DETAIL ""
#endif

static int32_t unsupported(rok_error *err) {
	if (err != NULL) {
		err->code = ROK_ERR_UNSUPPORTED;
		err->_pad = 0;
		set_buf(&err->message, "oci-cri engine is available on Linux only");
		set_buf(&err->detail, ROK_STUB_DETAIL);
	}
	return ROK_ERR_UNSUPPORTED;
}

int32_t rok_startup(rok_error *err) { return unsupported(err); }

int32_t rok_call(const char *request, rok_stdio_fn stdio_fn, void *stdio_user,
		 rok_input_fn input_fn, void *input_user, rok_buffer *out, rok_error *err) {
	(void)request;
	(void)stdio_fn;
	(void)stdio_user;
	(void)input_fn;
	(void)input_user;
	(void)out;
	return unsupported(err);
}

int32_t rok_diagnose(rok_buffer *out, rok_error *err) {
	(void)out;
	return unsupported(err);
}

void rok_buffer_free(rok_buffer *buf) {
	if (buf == NULL) {
		return;
	}
	free(buf->data);
	buf->data = NULL;
	buf->len = 0;
}

void rok_error_free(rok_error *err) {
	if (err == NULL) {
		return;
	}
	rok_buffer_free(&err->message);
	rok_buffer_free(&err->detail);
	err->code = 0;
}
