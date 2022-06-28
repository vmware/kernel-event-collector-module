/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

#ifdef CONFIG_SECURITY_PATH
// No preaction needed for now
#else
struct dynsec_config;
extern bool register_preaction_hooks(struct dynsec_config *dynsec_config);
extern void preaction_hooks_shutdown(void);
#endif /* !CONFIG_SECURITY_PATH */
