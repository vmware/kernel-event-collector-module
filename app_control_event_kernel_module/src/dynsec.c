// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include "lsm_mask.h"
#include "symbols.h"

#include "stall_reqs.h"
#include "path_utils.h"
#include "task_utils.h"
#include "tracepoints.h"
#include "inode_cache.h"
#include "task_cache.h"
#include "preaction_hooks.h"
#include "config.h"
#include "protect.h"

// Current contains most of possibly enabled LSM hooks
// except for file CLOSE.
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
        DYNSEC_HOOK_TYPE_MMAP      |\
        DYNSEC_HOOK_TYPE_CLOSE     |\
        DYNSEC_HOOK_TYPE_INODE_FREE)

#define DYNSEC_PROCESS_HOOKS (\
        DYNSEC_HOOK_TYPE_CLONE | \
        DYNSEC_HOOK_TYPE_EXIT | \
        DYNSEC_HOOK_TYPE_TASK_FREE)

// Used only for module_param
static uint32_t process_hooks = DYNSEC_PROCESS_HOOKS;

static char lsm_hooks_str[64];

bool protect_on_connect = false;

uint32_t stall_timeout_ctr_limit = DYNSEC_STALL_TIMEOUT_CTR_LIMIT;

// Hooks to only allow for kmod instance. Superset.
module_param_string(lsm_hooks, lsm_hooks_str,
                    sizeof(lsm_hooks_str), 0644);

module_param(process_hooks, uint, 0644);
module_param(protect_on_connect, bool, 0644);
module_param(stall_timeout_ctr_limit, uint, 0644);

// Special Globals
DEFINE_MUTEX(global_config_lock);
DEFINE_DYNSEC_CONFIG(global_config);
DEFINE_DYNSEC_CONFIG(preserved_config);

static void print_config(struct dynsec_config *dynsec_config)
{
    if (!dynsec_config) {
        return;
    }

    pr_info("dynsec_config: bypass_mode:%d stall_mode:%d\n",
            dynsec_config->bypass_mode, dynsec_config->stall_mode);
    pr_info("dynsec_config: stall_timeout:%u\n", dynsec_config->stall_timeout);
    pr_info("dynsec_config: stall_timeout_continue:%u\n",
            dynsec_config->stall_timeout_continue);
    pr_info("dynsec_config: stall_timeout_deny:%u\n",
            dynsec_config->stall_timeout_deny);
    pr_info("dynsec_config: lazy_notifier:%d queue_threshold:%d notify_threshold:%d\n",
            dynsec_config->lazy_notifier, dynsec_config->queue_threshold,
            dynsec_config->notify_threshold);
    pr_info("dynsec_config: send_files %#x\n", dynsec_config->send_files);
    pr_info("dynsec_config: protect_mode: %#x\n", dynsec_config->protect_mode);
    pr_info("dynsec_config: ignore_mode: %#x\n", dynsec_config->ignore_mode);
    pr_info("dynsec_config: lsm_hooks:%#llx process_hooks:%#llx preaction_hooks:%#llx\n",
            dynsec_config->lsm_hooks, dynsec_config->process_hooks,
            dynsec_config->preaction_hooks);
    pr_info("dynsec_config: file system stall mask: %#llx\n", 
            dynsec_config->file_system_stall_mask);
}

static void setup_lsm_hooks(void)
{
    uint64_t process_hooks_mask;

    // Set hooks kmod instance may allow.
    if (lsm_hooks_str[0]) {
        int strto_ret;
        uint64_t local_lsm_hooks = 0;

        lsm_hooks_str[sizeof(lsm_hooks_str) - 1] = 0;
        strto_ret = kstrtoull(lsm_hooks_str, 16, &local_lsm_hooks);
        if (!strto_ret) {
            global_config.lsm_hooks = local_lsm_hooks;
        }
    }

    // Ensure subset of event hooks only apply to set of process hooks.
    // Allow for completely disabled process hooks.
    process_hooks_mask = (process_hooks & DYNSEC_PROCESS_HOOKS);
    if (!process_hooks || process_hooks_mask) {
       global_config.process_hooks = process_hooks_mask;
    }
}

static int __init dynsec_init(void)
{
    pr_info("Initializing Dynamic Security Module Brand(%s)\n",
           THIS_MODULE->name);

    // Explicitly enable protection on connect
    (void)dynsec_protect_init();

    setup_lsm_hooks();

    if (!dynsec_sym_init()) {
        return -EINVAL;
    }

    if (!dynsec_path_utils_init()) {
        return -EINVAL;
    }
    dynsec_task_utils_init();

    if (!dynsec_init_tp(&global_config)) {
        pr_err("Unable to load process tracepoints\n");
        return -EINVAL;
    }

    if (!dynsec_init_lsmhooks(&global_config)) {
        pr_err("Unable to load LSM hooks\n");
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
    if (may_enable_inode_cache()) {
        inode_cache_register();
    }
    register_preaction_hooks(&global_config);

    dynsec_register_proc_entries();

    pr_info("Loaded: %s\n", CB_APP_MODULE_NAME);
    print_config(&global_config);

    lock_config();
    // struct copy the inital copy of the config data
    preserved_config = global_config;
    unlock_config();

    return 0;
}

static void __exit dynsec_exit(void)
{
    pr_info("Exiting: %s\n", THIS_MODULE->name);

    dynsec_cleanup_proc_entries();

    dynsec_protect_shutdown();

    dynsec_chrdev_shutdown();

    inode_cache_shutdown();

    task_cache_shutdown();

    dynsec_tp_shutdown();

    dynsec_lsm_shutdown();

    preaction_hooks_shutdown();
}

module_init(dynsec_init);
module_exit(dynsec_exit);

MODULE_AUTHOR("VMware, Inc.");
MODULE_LICENSE("GPL");
