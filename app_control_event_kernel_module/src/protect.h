/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright 2022 VMware, Inc. All rights reserved.

#pragma once

extern bool protect_on_connect;

extern int dynsec_protect_init(void);

extern void dynsec_protect_shutdown(void);

extern void dynsec_enable_protect(void);

extern void dynsec_disable_protect(void);

extern bool dynsec_is_protect_enabled(void);

extern int handle_protect_on_open(const struct task_struct *task);

extern int handle_protect_ioc(unsigned long arg);

extern int dynsec_may_protect_kill(const struct task_struct *initiator,
                                   int signal);

extern int dynsec_may_protect_ptrace(const struct task_struct *src,
                                     const struct task_struct *target);
