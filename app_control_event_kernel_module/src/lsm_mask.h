/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

#include <linux/security.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
extern struct security_operations *g_original_ops_ptr;
#endif

struct dynsec_config;
extern bool dynsec_init_lsmhooks(struct dynsec_config *dynsec_config);
extern void dynsec_lsm_shutdown(void);
extern int check_lsm_hooks_changed(void);
extern bool may_enable_inode_cache(void);
