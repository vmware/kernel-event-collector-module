/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

struct dynsec_config;
extern bool dynsec_init_tp(struct dynsec_config *dynsec_config);
extern void dynsec_tp_shutdown(void);
extern bool may_enable_task_cache(void);
