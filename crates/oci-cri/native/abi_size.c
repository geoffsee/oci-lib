/* SPDX-License-Identifier: Apache-2.0 */
/* Host program. Prints Rust constants for the C ABI layout. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "rok_abi.h"

int main(void) {
#if UINTPTR_MAX < UINT64_MAX
	fprintf(stderr, "abi_size: 64-bit pointers required\n");
	return 1;
#else
#define FIELD(struct_name, field, sym) \
	printf("pub const " sym ": usize = %zu;\n", offsetof(struct_name, field))

	printf("pub const ROK_BUFFER_SIZE: usize = %zu;\n", sizeof(rok_buffer));
	printf("pub const ROK_BUFFER_ALIGN: usize = %zu;\n", _Alignof(rok_buffer));
	FIELD(rok_buffer, data, "ROK_BUFFER_OFF_DATA");
	FIELD(rok_buffer, len, "ROK_BUFFER_OFF_LEN");

	printf("pub const ROK_ERROR_SIZE: usize = %zu;\n", sizeof(rok_error));
	printf("pub const ROK_ERROR_ALIGN: usize = %zu;\n", _Alignof(rok_error));
	FIELD(rok_error, code, "ROK_ERROR_OFF_CODE");
	FIELD(rok_error, message, "ROK_ERROR_OFF_MESSAGE");
	FIELD(rok_error, detail, "ROK_ERROR_OFF_DETAIL");
	return 0;
#endif
}
