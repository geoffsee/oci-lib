/* SPDX-License-Identifier: Apache-2.0 */
#ifndef ROB_ABI_H
#define ROB_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stable C ABI for the Buildah shim.
 *
 * Input strings are borrowed, NUL-terminated, and only valid for the call.
 * Output buffers are malloc'd, NUL-terminated, and len excludes the NUL.
 * A NULL data pointer with len 0 is an empty buffer.
 * Free every returned buffer with rob_buffer_free. rob_error_free and
 * rob_result_free free the buffers they contain.
 * Log callback bytes are valid only for the duration of the callback.
 * The callback runs on a Go thread: it must not call back into rob_* and
 * it must not unwind.
 * rob_buildah_version() is process-lifetime storage. Do not free it.
 * Integer error codes are also process exit codes. 0 is success.
 */

#define ROB_OK 0
#define ROB_ERR_INVALID 1
#define ROB_ERR_CANCELLED 2
#define ROB_ERR_NOT_FOUND 3
#define ROB_ERR_PREREQUISITE 4
#define ROB_ERR_BUILD 5
#define ROB_ERR_PUSH 6
#define ROB_ERR_TAG 7
#define ROB_ERR_UNSUPPORTED 8
#define ROB_ERR_INTERNAL 9
#define ROB_ERR_STATE 10

#define ROB_LOG_PROGRESS 0
#define ROB_LOG_INFO 1
#define ROB_LOG_WARN 2
#define ROB_LOG_ERROR 3

typedef void (*rob_log_fn)(void *user, int32_t level, const char *data, size_t len);

typedef struct rob_buffer {
	char *data;
	size_t len;
} rob_buffer;

typedef struct rob_error {
	int32_t code;
	int32_t _pad;
	rob_buffer message;
	rob_buffer detail;
} rob_error;

typedef struct rob_result {
	rob_buffer image_id;
	rob_buffer digest;
	rob_buffer reference;
} rob_result;

typedef struct rob_config {
	const char *storage_root;
	const char *run_root;
	const char *storage_driver;
	const char *registries_conf;
	const char *signature_policy;
	const char *auth_file;
	const char *log_level;
	const char *const *storage_opts;
	size_t storage_opt_count;
	int32_t insecure;
	int32_t _pad;
} rob_config;

typedef struct rob_build_request {
	const char *dockerfile;
	const char *context_dir;
	const char *tag;
	const char *target;
	const char *isolation;
	const char *format;
	const char *pull;
	const char *os_name;
	const char *arch;
	const char *variant;
	const char *const *build_arg_keys;
	const char *const *build_arg_vals;
	const char *const *labels;
	rob_log_fn log_fn;
	void *log_user;
	size_t build_arg_count;
	size_t label_count;
	uint64_t cancel_token;
	/* layers: -1 default (on), 0 off, 1 on */
	int32_t layers;
	int32_t no_cache;
	int32_t squash;
	int32_t quiet;
} rob_build_request;

typedef struct rob_push_request {
	const char *image;
	const char *destination;
	const char *username;
	const char *password;
	const char *format;
	rob_log_fn log_fn;
	void *log_user;
	uint64_t cancel_token;
	int32_t insecure;
	int32_t _pad;
} rob_push_request;

#if defined(__LP64__) || defined(_WIN64)
_Static_assert(sizeof(void *) == 8, "rob abi is LP64");
_Static_assert(sizeof(size_t) == 8, "rob abi size_t");
_Static_assert(sizeof(rob_buffer) == 16, "rob_buffer");
_Static_assert(sizeof(rob_error) == 40, "rob_error");
_Static_assert(sizeof(rob_result) == 48, "rob_result");
_Static_assert(sizeof(rob_config) == 80, "rob_config");
_Static_assert(sizeof(rob_build_request) == 160, "rob_build_request");
_Static_assert(sizeof(rob_push_request) == 72, "rob_push_request");
_Static_assert(offsetof(rob_error, message) == 8, "rob_error.message");
_Static_assert(offsetof(rob_config, storage_opts) == 56, "rob_config.storage_opts");
_Static_assert(offsetof(rob_config, insecure) == 72, "rob_config.insecure");
_Static_assert(offsetof(rob_build_request, log_fn) == 104, "rob_build_request.log_fn");
_Static_assert(offsetof(rob_build_request, cancel_token) == 136, "rob_build_request.cancel_token");
_Static_assert(offsetof(rob_build_request, layers) == 144, "rob_build_request.layers");
_Static_assert(offsetof(rob_push_request, log_fn) == 40, "rob_push_request.log_fn");
_Static_assert(offsetof(rob_push_request, cancel_token) == 56, "rob_push_request.cancel_token");
_Static_assert(offsetof(rob_push_request, insecure) == 64, "rob_push_request.insecure");
#endif

#ifdef __cplusplus
}
#endif

#endif /* ROB_ABI_H */
