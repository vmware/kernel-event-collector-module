// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include "lsm_mask.h"
#include "version.h"
#include "symbols.h"

#include "stall_reqs.h"
#include "logging.h"
#include "path_utils.h"
#include "task_utils.h"
#include "tracepoints.h"
#include "task_cache.h"
#include "preaction_hooks.h"

#define DYNSEC_LSM_HOOKS (\
        DYNSEC_HOOK_TYPE_EXEC      |\
        DYNSEC_HOOK_TYPE_UNLINK    |\
        DYNSEC_HOOK_TYPE_RMDIR     |\
        DYNSEC_HOOK_TYPE_RENAME    |\
        DYNSEC_HOOK_TYPE_SETATTR   |\
        DYNSEC_HOOK_TYPE_CREATE    |\
        DYNSEC_HOOK_TYPE_MKDIR     |\
        DYNSEC_HOOK_TYPE_LINK      |\
        DYNSEC_HOOK_TYPE_SYMLINK   |\
        DYNSEC_HOOK_TYPE_OPEN      |\
        DYNSEC_HOOK_TYPE_PTRACE    |\
        DYNSEC_HOOK_TYPE_SIGNAL    |\
        DYNSEC_HOOK_TYPE_MMAP)

uint64_t lsm_hooks_mask = DYNSEC_LSM_HOOKS;

uint32_t tracepoint_hooks = (
        DYNSEC_TP_HOOK_TYPE_CLONE |
        DYNSEC_TP_HOOK_TYPE_EXIT |
        DYNSEC_TP_HOOK_TYPE_TASK_FREE
);

static char lsm_hooks_str[64];
// Hooks to only allow for kmod instance. Superset.
module_param_string(lsm_hooks, lsm_hooks_str,
                    sizeof(lsm_hooks_str), 0644);

module_param(tracepoint_hooks, uint, 0644);

static void setup_lsm_hooks(void)
{
    int strto_ret;

    // Set hooks kmod instance may allow.
    if (lsm_hooks_str[0])
    {
        uint64_t local_lsm_hooks = 0;

        lsm_hooks_str[sizeof(lsm_hooks_str) - 1] = 0;
        strto_ret = kstrtoull(lsm_hooks_str, 16, &local_lsm_hooks);
        if (!strto_ret)
        {
            lsm_hooks_mask = local_lsm_hooks;
        }
    }
}

static int __init dynsec_init(void)
{
    DS_LOG(DS_INFO, "Initializing Dynamic Security Module Brand(%s)",
           CB_APP_MODULE_NAME);

    setup_lsm_hooks();

    if (!dynsec_sym_init()) {
        return -EINVAL;
    }

    if (!dynsec_path_utils_init()) {
        return -EINVAL;
    }
    dynsec_task_utils_init();

    if (!dynsec_init_tp(tracepoint_hooks)) {
        pr_info("Unable to load process tracepoints\n");
        return -EINVAL;
    }

    if (!dynsec_init_lsmhooks(lsm_hooks_mask)) {
        pr_info("Unable to load LSM hooks\n");
        dynsec_tp_shutdown();
        return -EINVAL;
    }

    if (!dynsec_chrdev_init()) {
        dynsec_tp_shutdown();
        dynsec_lsm_shutdown();
        return -EINVAL;
    }

    // Depends on process events
    if (may_enable_task_cache()) {
        task_cache_register();
    }
    register_preaction_hooks(lsm_hooks_mask);

    pr_info("Loaded DynSec\n");

    return 0;
}

static void __exit dynsec_exit(void)
{
    DS_LOG(DS_INFO, "Exiting Dynamic Security Module Brand(%s)",
           CB_APP_MODULE_NAME);

    dynsec_chrdev_shutdown();

    dynsec_tp_shutdown();

    dynsec_lsm_shutdown();

    preaction_hooks_shutdown();
}

module_init(dynsec_init);
module_exit(dynsec_exit);

MODULE_LICENSE("GPL");
