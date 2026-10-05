/* SPDX-License-Identifier: Apache-2.0 */
/* Host program. Prints Rust constants for the C ABI layout. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "ror_abi.h"

int main(void) {
#if UINTPTR_MAX < UINT64_MAX
	fprintf(stderr, "abi_size: 64-bit pointers required\n");
	return 1;
#else
#define FIELD(struct_name, field, sym) \
	printf("pub const " sym ": usize = %zu;\n", offsetof(struct_name, field))

	printf("pub const ROR_BUFFER_SIZE: usize = %zu;\n", sizeof(ror_buffer));
	printf("pub const ROR_BUFFER_ALIGN: usize = %zu;\n", _Alignof(ror_buffer));
	FIELD(ror_buffer, data, "ROR_BUFFER_OFF_DATA");
	FIELD(ror_buffer, len, "ROR_BUFFER_OFF_LEN");

	printf("pub const ROR_ERROR_SIZE: usize = %zu;\n", sizeof(ror_error));
	printf("pub const ROR_ERROR_ALIGN: usize = %zu;\n", _Alignof(ror_error));
	FIELD(ror_error, code, "ROR_ERROR_OFF_CODE");
	FIELD(ror_error, message, "ROR_ERROR_OFF_MESSAGE");
	FIELD(ror_error, detail, "ROR_ERROR_OFF_DETAIL");

	printf("pub const ROR_RUN_REQUEST_SIZE: usize = %zu;\n", sizeof(ror_run_request));
	printf("pub const ROR_RUN_REQUEST_ALIGN: usize = %zu;\n", _Alignof(ror_run_request));
	FIELD(ror_run_request, rootfs, "ROR_RUN_OFF_ROOTFS");
	FIELD(ror_run_request, cwd, "ROR_RUN_OFF_CWD");
	FIELD(ror_run_request, hostname, "ROR_RUN_OFF_HOSTNAME");
	FIELD(ror_run_request, state_root, "ROR_RUN_OFF_STATE_ROOT");
	FIELD(ror_run_request, argv, "ROR_RUN_OFF_ARGV");
	FIELD(ror_run_request, env, "ROR_RUN_OFF_ENV");
	FIELD(ror_run_request, stdio_fn, "ROR_RUN_OFF_STDIO_FN");
	FIELD(ror_run_request, stdio_user, "ROR_RUN_OFF_STDIO_USER");
	FIELD(ror_run_request, argv_count, "ROR_RUN_OFF_ARGV_COUNT");
	FIELD(ror_run_request, env_count, "ROR_RUN_OFF_ENV_COUNT");
	FIELD(ror_run_request, isolate_network, "ROR_RUN_OFF_ISOLATE_NETWORK");
	return 0;
#endif
}
