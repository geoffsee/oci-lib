/* SPDX-License-Identifier: Apache-2.0 */
#ifndef ROR_ABI_H
#define ROR_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stable C ABI for the libcontainer shim.
 *
 * Input strings are borrowed, NUL-terminated, and only valid for the call.
 * Output buffers are malloc'd, NUL-terminated, and len excludes the NUL.
 * A NULL data pointer with len 0 is an empty buffer.
 * Free every returned buffer with ror_buffer_free. ror_error_free frees the
 * buffers it contains.
 * The stdio callback bytes are valid only for the duration of the callback.
 * The callback runs on a Go thread: it must not call back into ror_* and
 * it must not unwind. A NULL stdio function means the container inherits
 * the process standard streams.
 * Integer error codes are also process exit codes. 0 is success.
 */

#define ROR_OK 0
#define ROR_ERR_INVALID 1
#define ROR_ERR_NOT_FOUND 3
#define ROR_ERR_PREREQUISITE 4
#define ROR_ERR_RUN 5
#define ROR_ERR_UNSUPPORTED 8
#define ROR_ERR_INTERNAL 9
#define ROR_ERR_STATE 10

#define ROR_STDOUT 1
#define ROR_STDERR 2

typedef void (*ror_stdio_fn)(void *user, int32_t stream, const char *data, size_t len);

typedef struct ror_buffer {
	char *data;
	size_t len;
} ror_buffer;

typedef struct ror_error {
	int32_t code;
	int32_t _pad;
	ror_buffer message;
	ror_buffer detail;
} ror_error;

typedef struct ror_run_request {
	const char *rootfs;
	const char *cwd;
	const char *hostname;
	const char *state_root;
	const char *const *argv;
	const char *const *env;
	ror_stdio_fn stdio_fn;
	void *stdio_user;
	size_t argv_count;
	size_t env_count;
	int32_t isolate_network;
	int32_t _pad;
} ror_run_request;

#if defined(__LP64__) || defined(_WIN64)
_Static_assert(sizeof(void *) == 8, "ror abi is LP64");
_Static_assert(sizeof(size_t) == 8, "ror abi size_t");
_Static_assert(sizeof(ror_buffer) == 16, "ror_buffer");
_Static_assert(sizeof(ror_error) == 40, "ror_error");
_Static_assert(sizeof(ror_run_request) == 88, "ror_run_request");
_Static_assert(offsetof(ror_error, message) == 8, "ror_error.message");
_Static_assert(offsetof(ror_run_request, argv) == 32, "ror_run_request.argv");
_Static_assert(offsetof(ror_run_request, stdio_fn) == 48, "ror_run_request.stdio_fn");
_Static_assert(offsetof(ror_run_request, argv_count) == 64, "ror_run_request.argv_count");
_Static_assert(offsetof(ror_run_request, isolate_network) == 80, "ror_run_request.isolate_network");
#endif

#ifdef __cplusplus
}
#endif

#endif /* ROR_ABI_H */
