/* SPDX-License-Identifier: Apache-2.0 */
/* Host program. Prints Rust constants for the C ABI layout. */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "rob_abi.h"

int main(void) {
#if UINTPTR_MAX < UINT64_MAX
	fprintf(stderr, "abi_size: 64-bit pointers required\n");
	return 1;
#else
#define FIELD(struct_name, field, sym) \
	printf("pub const " sym ": usize = %zu;\n", offsetof(struct_name, field))

	printf("pub const ROB_BUFFER_SIZE: usize = %zu;\n", sizeof(rob_buffer));
	printf("pub const ROB_BUFFER_ALIGN: usize = %zu;\n", _Alignof(rob_buffer));
	FIELD(rob_buffer, data, "ROB_BUFFER_OFF_DATA");
	FIELD(rob_buffer, len, "ROB_BUFFER_OFF_LEN");

	printf("pub const ROB_ERROR_SIZE: usize = %zu;\n", sizeof(rob_error));
	printf("pub const ROB_ERROR_ALIGN: usize = %zu;\n", _Alignof(rob_error));
	FIELD(rob_error, code, "ROB_ERROR_OFF_CODE");
	FIELD(rob_error, message, "ROB_ERROR_OFF_MESSAGE");
	FIELD(rob_error, detail, "ROB_ERROR_OFF_DETAIL");

	printf("pub const ROB_RESULT_SIZE: usize = %zu;\n", sizeof(rob_result));
	printf("pub const ROB_RESULT_ALIGN: usize = %zu;\n", _Alignof(rob_result));
	FIELD(rob_result, image_id, "ROB_RESULT_OFF_IMAGE_ID");
	FIELD(rob_result, digest, "ROB_RESULT_OFF_DIGEST");
	FIELD(rob_result, reference, "ROB_RESULT_OFF_REFERENCE");

	printf("pub const ROB_CONFIG_SIZE: usize = %zu;\n", sizeof(rob_config));
	printf("pub const ROB_CONFIG_ALIGN: usize = %zu;\n", _Alignof(rob_config));
	FIELD(rob_config, storage_root, "ROB_CONFIG_OFF_STORAGE_ROOT");
	FIELD(rob_config, run_root, "ROB_CONFIG_OFF_RUN_ROOT");
	FIELD(rob_config, storage_driver, "ROB_CONFIG_OFF_STORAGE_DRIVER");
	FIELD(rob_config, registries_conf, "ROB_CONFIG_OFF_REGISTRIES_CONF");
	FIELD(rob_config, signature_policy, "ROB_CONFIG_OFF_SIGNATURE_POLICY");
	FIELD(rob_config, auth_file, "ROB_CONFIG_OFF_AUTH_FILE");
	FIELD(rob_config, log_level, "ROB_CONFIG_OFF_LOG_LEVEL");
	FIELD(rob_config, storage_opts, "ROB_CONFIG_OFF_STORAGE_OPTS");
	FIELD(rob_config, storage_opt_count, "ROB_CONFIG_OFF_STORAGE_OPT_COUNT");
	FIELD(rob_config, insecure, "ROB_CONFIG_OFF_INSECURE");

	printf("pub const ROB_BUILD_REQUEST_SIZE: usize = %zu;\n", sizeof(rob_build_request));
	printf("pub const ROB_BUILD_REQUEST_ALIGN: usize = %zu;\n", _Alignof(rob_build_request));
	FIELD(rob_build_request, dockerfile, "ROB_BUILD_OFF_DOCKERFILE");
	FIELD(rob_build_request, context_dir, "ROB_BUILD_OFF_CONTEXT_DIR");
	FIELD(rob_build_request, tag, "ROB_BUILD_OFF_TAG");
	FIELD(rob_build_request, target, "ROB_BUILD_OFF_TARGET");
	FIELD(rob_build_request, isolation, "ROB_BUILD_OFF_ISOLATION");
	FIELD(rob_build_request, format, "ROB_BUILD_OFF_FORMAT");
	FIELD(rob_build_request, pull, "ROB_BUILD_OFF_PULL");
	FIELD(rob_build_request, os_name, "ROB_BUILD_OFF_OS_NAME");
	FIELD(rob_build_request, arch, "ROB_BUILD_OFF_ARCH");
	FIELD(rob_build_request, variant, "ROB_BUILD_OFF_VARIANT");
	FIELD(rob_build_request, build_arg_keys, "ROB_BUILD_OFF_BUILD_ARG_KEYS");
	FIELD(rob_build_request, build_arg_vals, "ROB_BUILD_OFF_BUILD_ARG_VALS");
	FIELD(rob_build_request, labels, "ROB_BUILD_OFF_LABELS");
	FIELD(rob_build_request, log_fn, "ROB_BUILD_OFF_LOG_FN");
	FIELD(rob_build_request, log_user, "ROB_BUILD_OFF_LOG_USER");
	FIELD(rob_build_request, build_arg_count, "ROB_BUILD_OFF_BUILD_ARG_COUNT");
	FIELD(rob_build_request, label_count, "ROB_BUILD_OFF_LABEL_COUNT");
	FIELD(rob_build_request, cancel_token, "ROB_BUILD_OFF_CANCEL_TOKEN");
	FIELD(rob_build_request, layers, "ROB_BUILD_OFF_LAYERS");
	FIELD(rob_build_request, no_cache, "ROB_BUILD_OFF_NO_CACHE");
	FIELD(rob_build_request, squash, "ROB_BUILD_OFF_SQUASH");
	FIELD(rob_build_request, quiet, "ROB_BUILD_OFF_QUIET");
	FIELD(rob_build_request, excludes, "ROB_BUILD_OFF_EXCLUDES");
	FIELD(rob_build_request, exclude_count, "ROB_BUILD_OFF_EXCLUDE_COUNT");

	printf("pub const ROB_PUSH_REQUEST_SIZE: usize = %zu;\n", sizeof(rob_push_request));
	printf("pub const ROB_PUSH_REQUEST_ALIGN: usize = %zu;\n", _Alignof(rob_push_request));
	FIELD(rob_push_request, image, "ROB_PUSH_OFF_IMAGE");
	FIELD(rob_push_request, destination, "ROB_PUSH_OFF_DESTINATION");
	FIELD(rob_push_request, username, "ROB_PUSH_OFF_USERNAME");
	FIELD(rob_push_request, password, "ROB_PUSH_OFF_PASSWORD");
	FIELD(rob_push_request, format, "ROB_PUSH_OFF_FORMAT");
	FIELD(rob_push_request, log_fn, "ROB_PUSH_OFF_LOG_FN");
	FIELD(rob_push_request, log_user, "ROB_PUSH_OFF_LOG_USER");
	FIELD(rob_push_request, cancel_token, "ROB_PUSH_OFF_CANCEL_TOKEN");
	FIELD(rob_push_request, insecure, "ROB_PUSH_OFF_INSECURE");
	return 0;
#endif
}
