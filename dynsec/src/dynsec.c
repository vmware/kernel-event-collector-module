// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/version.h>
#include "lsm_mask.h"
#include "version.h"
#include "symbols.h"
#include "dynsec.h"
#include "stall_reqs.h"
#include "logging.h"

// LSM Hooks / Event Types We Want to Enable On Default
// TODO: Make this overridable via module param
#define DYNSEC_LSM_default (DYNSEC_LSM_bprm_set_creds)

//
// Our hook for exec
//
int dynsec_bprm_set_creds(struct linux_binprm *bprm)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    int response = 0;
    int rc;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->bprm_set_creds(bprm);
        if (ret) {
            goto out;
        }
    }
#endif
    if (!bprm || !bprm->file) {
        goto out;
    }

    if (!current->real_parent) {
        goto out;
    }
    if (current->tgid <= 2) {
        goto out;
    }
    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }

    // TODO: check if stall_tbl's connected tgid matches

    event = alloc_dynsec_event(DYNSEC_LSM_bprm_set_creds, GFP_KERNEL);
    if (!event) {
        goto out;
    }
    if (fill_in_bprm_set_creds(dynsec_event_to_exec(event), bprm,
                               GFP_KERNEL)) {
        rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);
        if (!rc) {
            ret = response;
        }
    } else {
        free_dynsec_event(event);
    }
    event = NULL;

out:

    return ret;
}

static int __init dynsec_init(void)
{
    DS_LOG(DS_INFO, "Initializing Dynamic Security Module Brand(%s)",
           CB_APP_MODULE_NAME);

    if (!dynsec_sym_init()) {
        return -EINVAL;
    }

    if (!dynsec_chrdev_init()) {
        return -EINVAL;
    }

    if (!dynsec_init_lsmhooks(DYNSEC_LSM_default)) {
        dynsec_chrdev_shutdown();
        return -EINVAL;
    }

    return 0;
}

static void __exit dynsec_exit(void)
{
    DS_LOG(DS_INFO, "Exiting Dynamic Security Module Brand(%s)",
           CB_APP_MODULE_NAME);

    dynsec_lsm_shutdown();

    dynsec_chrdev_shutdown();
}

module_init(dynsec_init);
module_exit(dynsec_exit);

MODULE_LICENSE("GPL");
