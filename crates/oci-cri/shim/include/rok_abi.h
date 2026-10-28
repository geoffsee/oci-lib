/* SPDX-License-Identifier: Apache-2.0 */
#ifndef ROK_ABI_H
#define ROK_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stable C ABI for the oci-cri engine shim.
 *
 * One Go c-archive holds libcontainer and containers/image+storage, so the
 * whole CRI engine is a single JSON call: rok_call takes a NUL-terminated
 * JSON request ("op" selects the operation) and returns a JSON response in
 * an malloc'd buffer. Free output with rok_buffer_free, errors with
 * rok_error_free.
 *
 * The stdio callback bytes are valid only for the duration of the callback
 * and it runs on a Go thread: it must not call back into rok_* and must not
 * unwind. For long-lived containers the callback supplied to "start" stays
 * registered in the shim until "wait" returns.
 *
 * The input callback fills buf with stdin bytes and returns the count, 0
 * for EOF, or a negative value on error. It may block.
 *
 * Integer error codes are also process exit codes. 0 is success.
 */

#define ROK_OK 0
#define ROK_ERR_INVALID 1
#define ROK_ERR_NOT_FOUND 3
#define ROK_ERR_PREREQUISITE 4
#define ROK_ERR_RUN 5
#define ROK_ERR_UNSUPPORTED 8
#define ROK_ERR_INTERNAL 9
#define ROK_ERR_STATE 10

#define ROK_STDOUT 1
#define ROK_STDERR 2

typedef void (*rok_stdio_fn)(void *user, int32_t stream, const char *data, size_t len);
typedef intptr_t (*rok_input_fn)(void *user, char *buf, size_t cap);

typedef struct rok_buffer {
	char *data;
	size_t len;
} rok_buffer;

typedef struct rok_error {
	int32_t code;
	int32_t _pad;
	rok_buffer message;
	rok_buffer detail;
} rok_error;

#if defined(__LP64__) || defined(_WIN64)
_Static_assert(sizeof(void *) == 8, "rok abi is LP64");
_Static_assert(sizeof(size_t) == 8, "rok abi size_t");
_Static_assert(sizeof(rok_buffer) == 16, "rok_buffer");
_Static_assert(sizeof(rok_error) == 40, "rok_error");
_Static_assert(offsetof(rok_error, message) == 8, "rok_error.message");
#endif

#ifdef __cplusplus
}
#endif

#endif /* ROK_ABI_H */
