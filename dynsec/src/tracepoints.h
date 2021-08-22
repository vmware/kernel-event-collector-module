/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once
extern bool dynsec_init_tp(uint32_t tp_hooks);
extern void dynsec_tp_shutdown(void);
extern bool may_enable_task_cache(void);
