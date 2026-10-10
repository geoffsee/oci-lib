/* SPDX-License-Identifier: Apache-2.0 */
/* Non-Linux stand-in for the Buildah c-archive. Same ABI, no engine. */

#include "rob.h"

#include <stdlib.h>
#include <string.h>

static uint64_t next_token = 1;

static void set_buf(rob_buffer *b, const char *s) {
	size_t n;
	char *p;
	if (b == NULL) {
		return;
	}
	if (s == NULL) {
		s = "";
	}
	n = strlen(s);
	if (n == 0) {
		b->data = NULL;
		b->len = 0;
		return;
	}
	p = (char *)malloc(n + 1);
	if (p == NULL) {
		b->data = NULL;
		b->len = 0;
		return;
	}
	memcpy(p, s, n + 1);
	b->data = p;
	b->len = n;
}

/* build.rs sets this on macOS builds with the `vm` feature turned off. */
#ifndef ROB_STUB_DETAIL
#define ROB_STUB_DETAIL ""
#endif

static int32_t unsupported(rob_error *err) {
	if (err != NULL) {
		err->code = ROB_ERR_UNSUPPORTED;
		err->_pad = 0;
		set_buf(&err->message, "Buildah is available on Linux only");
		set_buf(&err->detail, ROB_STUB_DETAIL);
	}
	return ROB_ERR_UNSUPPORTED;
}

int32_t rob_startup(rob_error *err) { return unsupported(err); }

int32_t rob_init(const rob_config *cfg, rob_error *err) {
	(void)cfg;
	return unsupported(err);
}

int32_t rob_shutdown(rob_error *err) {
	(void)err;
	return ROB_OK;
}

int32_t rob_build(const rob_build_request *req, rob_result *out, rob_error *err) {
	(void)req;
	(void)out;
	return unsupported(err);
}

int32_t rob_tag(const char *image, const char *new_name, rob_error *err) {
	(void)image;
	(void)new_name;
	return unsupported(err);
}

int32_t rob_push(const rob_push_request *req, rob_result *out, rob_error *err) {
	(void)req;
	(void)out;
	return unsupported(err);
}

int32_t rob_diagnose(rob_buffer *out, rob_error *err) {
	(void)out;
	return unsupported(err);
}

uint64_t rob_cancel_new(void) {
	uint64_t id = next_token++;
	if (next_token == 0) {
		next_token = 1;
	}
	return id;
}

void rob_cancel(uint64_t token) { (void)token; }

void rob_cancel_free(uint64_t token) { (void)token; }

void rob_buffer_free(rob_buffer *buf) {
	if (buf == NULL) {
		return;
	}
	free(buf->data);
	buf->data = NULL;
	buf->len = 0;
}

void rob_error_free(rob_error *err) {
	if (err == NULL) {
		return;
	}
	rob_buffer_free(&err->message);
	rob_buffer_free(&err->detail);
	err->code = 0;
}

void rob_result_free(rob_result *res) {
	if (res == NULL) {
		return;
	}
	rob_buffer_free(&res->image_id);
	rob_buffer_free(&res->digest);
	rob_buffer_free(&res->reference);
}

const char *rob_buildah_version(void) { return "unsupported"; }
