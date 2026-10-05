/* SPDX-License-Identifier: Apache-2.0 */
#ifndef ROB_H
#define ROB_H

#include "rob_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Fallible calls return a ROB_OK / ROB_ERR_* code and, on failure, fill
 * err when err is non-NULL. err must be zeroed by the caller. On success
 * the result struct is filled when the call produces one.
 *
 * Token 0 means "no cancellation". rob_cancel_free drops the token and does
 * not cancel. A token that is unknown or already freed at the start of an
 * operation is treated as already cancelled. The token must outlive the
 * operation that uses it.
 *
 * rob_startup must run at the beginning of main, before threads are created,
 * so Buildah re-exec handlers and the rootless user namespace see a fresh
 * process. It may re-exec the process and not return.
 */

int32_t rob_startup(rob_error *err);
int32_t rob_init(const rob_config *cfg, rob_error *err);
int32_t rob_shutdown(rob_error *err);
int32_t rob_build(const rob_build_request *req, rob_result *out, rob_error *err);
int32_t rob_tag(const char *image, const char *new_name, rob_error *err);
int32_t rob_push(const rob_push_request *req, rob_result *out, rob_error *err);
int32_t rob_diagnose(rob_buffer *out, rob_error *err);

uint64_t rob_cancel_new(void);
void rob_cancel(uint64_t token);
void rob_cancel_free(uint64_t token);

void rob_buffer_free(rob_buffer *buf);
void rob_error_free(rob_error *err);
void rob_result_free(rob_result *res);

const char *rob_buildah_version(void);

#ifdef __cplusplus
}
#endif

#endif /* ROB_H */
