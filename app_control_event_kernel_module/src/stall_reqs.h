/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

// Call within LSM hook
#include "factory.h"
#include "stall_tbl.h"
extern struct stall_tbl *stall_tbl;

extern bool task_in_connected_tgid(const struct task_struct *task);

extern bool dynsec_chrdev_init(void);
extern void dynsec_register_proc_entries(void);

extern void dynsec_chrdev_shutdown(void);
extern void dynsec_cleanup_proc_entries(void);
