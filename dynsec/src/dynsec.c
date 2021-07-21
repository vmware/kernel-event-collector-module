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

// LSM Hooks / Event Types We Want to Enable On Default
// TODO: Make this overridable via module param
#define DYNSEC_LSM_default (\
    DYNSEC_HOOK_TYPE_EXEC      |\
    DYNSEC_HOOK_TYPE_UNLINK    |\
    DYNSEC_HOOK_TYPE_RMDIR     |\
    DYNSEC_HOOK_TYPE_RENAME    |\
    DYNSEC_HOOK_TYPE_SETATTR   |\
    DYNSEC_HOOK_TYPE_CREATE    |\
    DYNSEC_HOOK_TYPE_MKDIR)


static int __init dynsec_init(void)
{
    DS_LOG(DS_INFO, "Initializing Dynamic Security Module Brand(%s)",
           CB_APP_MODULE_NAME);

    if (!dynsec_sym_init()) {
        return -EINVAL;
    }

    if (!dynsec_path_utils_init()) {
        return -EINVAL;
    }

    if (!dynsec_init_lsmhooks(DYNSEC_LSM_default)) {
        return -EINVAL;
    }

    if (!dynsec_chrdev_init()) {
        dynsec_lsm_shutdown();
        return -EINVAL;
    }

    return 0;
}

static void __exit dynsec_exit(void)
{
    DS_LOG(DS_INFO, "Exiting Dynamic Security Module Brand(%s)",
           CB_APP_MODULE_NAME);

    dynsec_chrdev_shutdown();

    dynsec_lsm_shutdown();
}

module_init(dynsec_init);
module_exit(dynsec_exit);

MODULE_LICENSE("GPL");
