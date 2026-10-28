/* SPDX-License-Identifier: Apache-2.0 */
#ifndef ROK_H
#define ROK_H

#include "rok_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* rok_startup must run at the beginning of main, before threads are created.
 * The libcontainer init child is dispatched from the Go runtime before main;
 * startup exists so a re-exec is not parsed as a CLI.
 *
 * rok_call runs one JSON engine operation (see src/engine.rs for the op
 * vocabulary). On success out holds the JSON response. On failure the return
 * value is a ROK_ERR_* code and err is filled when non-NULL.
 */

int32_t rok_startup(rok_error *err);
int32_t rok_call(const char *request, rok_stdio_fn stdio_fn, void *stdio_user,
		 rok_input_fn input_fn, void *input_user, rok_buffer *out, rok_error *err);
int32_t rok_diagnose(rok_buffer *out, rok_error *err);

void rok_buffer_free(rok_buffer *buf);
void rok_error_free(rok_error *err);

#ifdef __cplusplus
}
#endif

#endif /* ROK_H */
