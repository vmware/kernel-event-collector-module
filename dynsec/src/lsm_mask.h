/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once
#include <linux/security.h>

extern uint64_t lsm_hooks_mask;     // Max set of hooks we may enable

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
extern struct security_operations *g_original_ops_ptr;
#endif

extern bool dynsec_init_lsmhooks(uint64_t enableHooks);
extern void dynsec_lsm_shutdown(void);
extern int check_lsm_hooks_changed(void);

