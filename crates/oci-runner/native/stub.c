/* SPDX-License-Identifier: Apache-2.0 */
/* Non-Linux stand-in for the libcontainer c-archive. Same ABI, no engine. */

#include "ror.h"

#include <stdlib.h>
#include <string.h>

static void set_buf(ror_buffer *buf, const char *text) {
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

static int32_t unsupported(ror_error *err) {
	if (err != NULL) {
		err->code = ROR_ERR_UNSUPPORTED;
		err->_pad = 0;
		set_buf(&err->message, "oci-runner is available on Linux and macOS only");
		set_buf(&err->detail, "");
	}
	return ROR_ERR_UNSUPPORTED;
}

int32_t ror_startup(ror_error *err) { return unsupported(err); }

int32_t ror_run(const ror_run_request *req, int32_t *exit_code, ror_error *err) {
	(void)req;
	if (exit_code != NULL) {
		*exit_code = 0;
	}
	return unsupported(err);
}

int32_t ror_diagnose(ror_buffer *out, ror_error *err) {
	(void)out;
	return unsupported(err);
}

void ror_buffer_free(ror_buffer *buf) {
	if (buf == NULL) {
		return;
	}
	free(buf->data);
	buf->data = NULL;
	buf->len = 0;
}

void ror_error_free(ror_error *err) {
	if (err == NULL) {
		return;
	}
	ror_buffer_free(&err->message);
	ror_buffer_free(&err->detail);
	err->code = 0;
}
