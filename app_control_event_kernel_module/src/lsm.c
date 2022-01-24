// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

// Adapted from kernel-event-collector-module
// kver 4.2 appears to be the kernel with the hook lists

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{
#include <linux/lsm_hooks.h>  // security_hook_heads
#endif  //}
#include <linux/rculist.h>  // hlist_add_tail_rcu
#include <linux/module.h>
#include "symbols.h"
#include "lsm_mask.h"
#include "dynsec.h"
#include "hooks.h"

// checkpatch-ignore: AVOID_EXTERNS
#define DEBUGGING_SANITY 0
#if DEBUGGING_SANITY  //{ WARNING from checkpatch
#define PR_p "%px"
#else  //}{ checkpatch no WARNING
#define PR_p "%p"
#endif  //}


// Event Type To LSM Hook Names
#define DYNSEC_LSM_inode_rename         DYNSEC_HOOK_TYPE_RENAME
#define DYNSEC_LSM_inode_unlink         DYNSEC_HOOK_TYPE_UNLINK
#define DYNSEC_LSM_inode_rmdir          DYNSEC_HOOK_TYPE_RMDIR
#define DYNSEC_LSM_inode_mkdir          DYNSEC_HOOK_TYPE_MKDIR
#define DYNSEC_LSM_inode_create         DYNSEC_HOOK_TYPE_CREATE
#define DYNSEC_LSM_inode_setattr        DYNSEC_HOOK_TYPE_SETATTR
#define DYNSEC_LSM_inode_link           DYNSEC_HOOK_TYPE_LINK
#define DYNSEC_LSM_inode_symlink        DYNSEC_HOOK_TYPE_SYMLINK
#define DYNSEC_LSM_inode_free_security  DYNSEC_HOOK_TYPE_INODE_FREE

// may need another hook
#define DYNSEC_LSM_bprm_set_creds       DYNSEC_HOOK_TYPE_EXEC

#define DYNSEC_LSM_task_kill            DYNSEC_HOOK_TYPE_SIGNAL
// depends on kver
#define DYNSEC_LSM_dentry_open          DYNSEC_HOOK_TYPE_OPEN
#define DYNSEC_LSM_file_open            DYNSEC_HOOK_TYPE_OPEN
#define DYNSEC_LSM_file_free_security   DYNSEC_HOOK_TYPE_CLOSE

// Ptrace hook type maps to two hooks
#define DYNSEC_LSM_ptrace_traceme       DYNSEC_HOOK_TYPE_PTRACE
#define DYNSEC_LSM_ptrace_access_check  DYNSEC_HOOK_TYPE_PTRACE
#define DYNSEC_LSM_task_free            DYNSEC_HOOK_TYPE_TASK_FREE
#define DYNSEC_LSM_mmap_file            DYNSEC_HOOK_TYPE_MMAP
#define DYNSEC_LSM_file_mmap            DYNSEC_HOOK_TYPE_MMAP


static bool g_lsmRegistered;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{ not RHEL8
struct        security_operations  *g_original_ops_ptr;   // Any LSM which we are layered on top of
static struct security_operations   g_combined_ops;       // Original LSM plus our hooks combined
#endif //}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{
static unsigned int cblsm_hooks_count;
static struct security_hook_list cblsm_hooks[64];  // [0..39] not needed?
#endif  //}

struct lsm_symbols {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    struct security_operations **security_ops;
#else
    struct security_hook_heads *security_hook_heads;
#endif
};

static struct lsm_symbols lsm_syms;
static struct lsm_symbols *p_lsm;
static uint64_t enabled_lsm_hooks;

bool dynsec_init_lsmhooks(struct dynsec_config *dynsec_config)
{
    uint64_t enableHooks = 0;

    enabled_lsm_hooks = 0;
    p_lsm = NULL;
    g_lsmRegistered = false;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    g_original_ops_ptr = NULL;
#endif

    if (!dynsec_config) {
        return false;
    }
    enableHooks = dynsec_config->lsm_hooks;

    // Add check when implementing LSM hooks
    BUILD_BUG_ON(DYNSEC_LSM_bprm_set_creds != DYNSEC_HOOK_TYPE_EXEC);
    BUILD_BUG_ON(DYNSEC_LSM_inode_rename   != DYNSEC_HOOK_TYPE_RENAME);
    BUILD_BUG_ON(DYNSEC_LSM_inode_unlink   != DYNSEC_HOOK_TYPE_UNLINK);
    BUILD_BUG_ON(DYNSEC_LSM_inode_rmdir    != DYNSEC_HOOK_TYPE_RMDIR);
    BUILD_BUG_ON(DYNSEC_LSM_inode_setattr  != DYNSEC_HOOK_TYPE_SETATTR);
    BUILD_BUG_ON(DYNSEC_LSM_inode_mkdir    != DYNSEC_HOOK_TYPE_MKDIR);
    BUILD_BUG_ON(DYNSEC_LSM_inode_free_security
                                           != DYNSEC_HOOK_TYPE_INODE_FREE);
    BUILD_BUG_ON(DYNSEC_LSM_dentry_open    != DYNSEC_HOOK_TYPE_OPEN);
    BUILD_BUG_ON(DYNSEC_LSM_file_open      != DYNSEC_HOOK_TYPE_OPEN);
    BUILD_BUG_ON(DYNSEC_LSM_file_free_security 
                                           != DYNSEC_HOOK_TYPE_CLOSE);
    BUILD_BUG_ON(DYNSEC_LSM_task_free 
                                           != DYNSEC_HOOK_TYPE_TASK_FREE);

    // Enforce security_file_free
    // if ((enableHooks & DYNSEC_HOOK_TYPE_OPEN) &&
    //     !(enableHooks & DYNSEC_HOOK_TYPE_CLOSE)) {
    //     pr_info("%s: CLOSE hook must be enabled  with "
    //             "OPEN hook. enabled:%#016llx\n", __func__, enableHooks);
    //     return false;
    // }

    memset(&lsm_syms, 0, sizeof(lsm_syms));

#define find_lsm_sym(sym_name, ops) \
    find_symbol_indirect(#sym_name, (unsigned long *)&ops.sym_name);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    find_lsm_sym(security_ops, lsm_syms);
    if (!lsm_syms.security_ops)
    {
        goto out_fail;
    }
#else
    find_lsm_sym(security_hook_heads, lsm_syms);
    if (!lsm_syms.security_hook_heads)
    {
        goto out_fail;
    }
#endif
    p_lsm = &lsm_syms;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    //
    // Save off the old LSM pointers
    //
    g_original_ops_ptr = *p_lsm->security_ops;
    if (g_original_ops_ptr != NULL)
    {
        g_combined_ops = *g_original_ops_ptr;
    }
    pr_info("Other LSM named %s", g_original_ops_ptr->name);

    #define CB_LSM_SETUP_HOOK(NAME) do { \
        if (enableHooks & DYNSEC_LSM_##NAME) {\
            enabled_lsm_hooks |= DYNSEC_LSM_##NAME; \
            g_combined_ops.NAME = dynsec_##NAME; \
        } \
    } while (0)

#else  // }{ LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    cblsm_hooks_count = 0;
    memset(cblsm_hooks, 0, sizeof(cblsm_hooks));

    #define CB_LSM_SETUP_HOOK(NAME) do { \
        if (p_lsm->security_hook_heads && enableHooks & DYNSEC_LSM_##NAME) { \
            enabled_lsm_hooks |= DYNSEC_LSM_##NAME; \
            pr_info("Hooking %u@" PR_p " %s\n", cblsm_hooks_count, &p_lsm->security_hook_heads->NAME, #NAME); \
            cblsm_hooks[cblsm_hooks_count].head = &p_lsm->security_hook_heads->NAME; \
            cblsm_hooks[cblsm_hooks_count].hook.NAME = dynsec_##NAME; \
            cblsm_hooks[cblsm_hooks_count].lsm = "dynsec"; \
            cblsm_hooks_count++; \
        } \
    } while (0)
#endif  // }

    //
    // Now add our hooks
    //
    CB_LSM_SETUP_HOOK(bprm_set_creds); // process banning  (exec)
    CB_LSM_SETUP_HOOK(inode_unlink);   // security_inode_unlink
    CB_LSM_SETUP_HOOK(inode_rmdir);   // security_inode_rmdir
    CB_LSM_SETUP_HOOK(inode_rename);   // security_inode_rename
    CB_LSM_SETUP_HOOK(inode_setattr);   // security_inode_setattr
    CB_LSM_SETUP_HOOK(inode_create);   // security_inode_create
    CB_LSM_SETUP_HOOK(inode_mkdir);   // security_inode_mkdir
    CB_LSM_SETUP_HOOK(inode_link);    //security_inode_link
    CB_LSM_SETUP_HOOK(inode_symlink);    //security_inode_symlink
    CB_LSM_SETUP_HOOK(inode_free_security); //security_inode_free
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    CB_LSM_SETUP_HOOK(dentry_open); // security_dentry_open
    CB_LSM_SETUP_HOOK(file_mmap);
#else
    CB_LSM_SETUP_HOOK(file_open);   // security_file_open
    CB_LSM_SETUP_HOOK(mmap_file);
    // CB_LSM_SETUP_HOOK(task_free);   // Prefer tracepoint instead of this
#endif

    CB_LSM_SETUP_HOOK(file_free_security);
    CB_LSM_SETUP_HOOK(ptrace_traceme);
    CB_LSM_SETUP_HOOK(ptrace_access_check);
    CB_LSM_SETUP_HOOK(task_kill);

#undef CB_LSM_SETUP_HOOK



#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    if (enabled_lsm_hooks) {
        *(p_lsm->security_ops) = &g_combined_ops;
    }
#else  //}{
    {
        unsigned int j;

        for (j = 0; j < cblsm_hooks_count; ++j) {
            cblsm_hooks[j].lsm = "dynsec";
            hlist_add_tail_rcu(&cblsm_hooks[j].list, cblsm_hooks[j].head);
        }
    }
#endif  //}

    g_lsmRegistered = true;

    if (dynsec_config) {
        dynsec_config->lsm_hooks = enabled_lsm_hooks;
    }
    return true;

out_fail:
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    pr_info("LSM: Failed to find security_ops\n");
#else  //}{
    pr_info("LSM: Failed to find security_hook_heads\n");
#endif  //}
    dynsec_config->lsm_hooks = enabled_lsm_hooks;

    return false;
}

// KERNEL_VERSION(4,0,0) and above say this is none of our business

int check_lsm_hooks_changed(void)
{
    int diff = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    struct security_operations *secops = NULL;
    char modname[MODULE_NAME_LEN + 1];

    if (!g_lsmRegistered) {
        return 0;
    }
    if (!enabled_lsm_hooks) {
        return 0;
    }
    if (!p_lsm) {
        return 0;
    }

    // Detect when something else may be referencing our LSM hooks
    if (*(p_lsm->security_ops) != &g_combined_ops) {
        dynsec_module_name((unsigned long)*(p_lsm->security_ops),
                               modname, MODULE_NAME_LEN);
        // Won't find kmod if secops dynamically allocated
        if (modname[0]) {
            pr_info("LSM security_ops Changed by: %s\n", modname);
        }
        // Something could be referencing our LSM hooks
        // but not overriding with their own.
        diff += 1;
    }

    secops = *(p_lsm->security_ops);
#define check_lsm_hook(NAME) do { \
        if (enabled_lsm_hooks & DYNSEC_LSM_##NAME) { \
            if (secops->NAME != g_combined_ops.NAME) { \
                diff += 1; \
                dynsec_module_name((unsigned long)secops->NAME, \
                                   modname, MODULE_NAME_LEN); \
                pr_info("LSM Hook " #NAME " Changed by: %s\n", modname); \
            } \
        } \
    } while (0)

    // Log who at where overrided specific hooks
    check_lsm_hook(bprm_set_creds);
    check_lsm_hook(inode_unlink);
    check_lsm_hook(inode_rmdir);
    check_lsm_hook(inode_rename);
    check_lsm_hook(inode_setattr);
    check_lsm_hook(inode_create);
    check_lsm_hook(inode_mkdir);
    check_lsm_hook(inode_link);
    check_lsm_hook(inode_symlink);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    check_lsm_hook(dentry_open);
    check_lsm_hook(file_mmap);
#else
    check_lsm_hook(file_open);
    check_lsm_hook(mmap_file);
    // check_lsm_hook(task_free);
#endif
    check_lsm_hook(file_free_security);

#undef check_lsm_hook

#endif //}

    return diff;
}

void dynsec_lsm_shutdown(void)
{
    if (g_lsmRegistered
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    &&     p_lsm && p_lsm->security_ops
#endif  //}
    )
    {
        pr_info("Unregistering dynsec LSM...");
        g_lsmRegistered = false;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
        *(p_lsm->security_ops) = g_original_ops_ptr;
        enabled_lsm_hooks = 0;
        p_lsm = NULL;
#else  // }{ >= KERNEL_VERSION(4,0,0)
        security_delete_hooks(cblsm_hooks, cblsm_hooks_count);
#endif  //}
    } else
    {
        pr_info("dynsec LSM not registered so not unregistering");
    }
}

bool may_enable_inode_cache(void)
{
    return (enabled_lsm_hooks & DYNSEC_HOOK_TYPE_OPEN);
}
