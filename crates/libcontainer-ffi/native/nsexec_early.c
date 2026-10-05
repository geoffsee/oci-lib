/* SPDX-License-Identifier: Apache-2.0 */
/*
 * libcontainer enters namespaces from the nsexec constructor so the re-exec
 * child is still single-threaded. In this c-archive that constructor shares
 * .init_array priority with the Go runtime, and the runtime wins, so the
 * child dies before main.
 *
 * Priority 101 runs after libc and before the Go runtime. nsexec is pure C.
 * It returns immediately unless this process is the re-exec child. Do not
 * call into Go from here. That races runtime init and can deadlock.
 *
 * Clearing _LIBCONTAINER_INITPIPE makes libcontainer/nsenter's later
 * constructor a no-op. Go init still reads _LIBCONTAINER_SYNCPIPE.
 */

#define _GNU_SOURCE

#include <stdlib.h>

extern void nsexec(void);

__attribute__((constructor(101))) static void ror_nsexec_before_go_runtime(void) {
	nsexec();
	unsetenv("_LIBCONTAINER_INITPIPE");
}

int ror_nsexec_keep(void) { return 0; }
