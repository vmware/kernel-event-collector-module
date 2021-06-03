/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once
#include <linux/security.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
extern struct security_operations *g_original_ops_ptr;
extern uint64_t g_enableHooks;
#endif

extern bool dynsec_init_lsmhooks(uint64_t enableHooks);
extern void dynsec_lsm_shutdown(void);

