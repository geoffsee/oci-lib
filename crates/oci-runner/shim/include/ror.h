/* SPDX-License-Identifier: Apache-2.0 */
#ifndef ROR_H
#define ROR_H

#include "ror_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Fallible calls return a ROR_OK / ROR_ERR_* code and, on failure, fill
 * err when err is non-NULL. err must be zeroed by the caller. On success
 * *exit_code is the container process status.
 *
 * ror_startup must run at the beginning of main, before threads are created.
 * The container init child is dispatched from the Go runtime before main;
 * startup exists so a re-exec is not parsed as a CLI.
 */

int32_t ror_startup(ror_error *err);
int32_t ror_run(const ror_run_request *req, int32_t *exit_code, ror_error *err);
int32_t ror_diagnose(ror_buffer *out, ror_error *err);

void ror_buffer_free(ror_buffer *buf);
void ror_error_free(ror_error *err);

#ifdef __cplusplus
}
#endif

#endif /* ROR_H */
