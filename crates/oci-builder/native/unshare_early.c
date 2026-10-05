/* SPDX-License-Identifier: Apache-2.0 */
/*
 * containers/storage enters a user namespace from a C constructor so the
 * re-exec child is still single-threaded. unshare(CLONE_NEWUSER) returns
 * EINVAL once any other thread exists. In this c-archive that constructor
 * shares .init_array priority with the Go runtime, and the runtime wins,
 * so the child dies before main.
 *
 * Priority 101 runs after libc and before the Go runtime. _containers_unshare
 * is pure C. It returns immediately unless this process is the re-exec child.
 * Do not call into Go from here. That races runtime init and can deadlock.
 */

extern void _containers_unshare(void);

__attribute__((constructor(101))) static void rob_unshare_before_go_runtime(void) {
	_containers_unshare();
}

int rob_unshare_keep(void) { return 0; }
