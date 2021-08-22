/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#pragma once

extern bool register_preaction_hooks(uint64_t lsm_hooks);
extern void preaction_hooks_shutdown(void);
