/* Copyright 2018 Carbon Black Inc.  All rights reserved. */

#include "opcache.h"
#include "usercomm.h"
#include "logging.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/kallsyms.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/cred.h>
#include <linux/version.h>
#include <linux/mount.h>
#include "lsm_mask.h"
#include "version.h"
#include "symbols.h"
#include "dynsec.h"
#include "stall_reqs.h"

#define DYNSEC_LSM_default (DYNSEC_LSM_bprm_set_creds)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Carbon Black, Inc.");
MODULE_DESCRIPTION("A Dynamic Security Module.");
MODULE_VERSION("0.01");

//
// Our hook for exec
//
int dynsec_bprm_set_creds(struct linux_binprm *bprm)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    int response = 0;
#if 0
    struct opcache_ctx ctx;
    bool found_dev = false;
    bool found_ino = false;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->bprm_set_creds(bprm);
        if (ret) {
            return ret;
        }
    }
#endif
    if (!bprm || !bprm->file) {
        return ret;
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
    // check if stall_tbl's tgid matches 

    event = alloc_dynsec_event(DYNSEC_LSM_bprm_set_creds, GFP_KERNEL);
    if (!event) {
        goto out;
    }
    if (fill_in_bprm_set_creds(dynsec_event_to_exec(event), bprm,
                               GFP_KERNEL)) {
        ret = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);
        if (ret != 0 || ret != -EPERM) {
            ret = 0;
        }
    } else {
        free_dynsec_event(event);
    }
    event = NULL;

#if 0
    if (!user_connected())
    {
        return ret;
    }

    if (bprm->file->f_path.dentry->d_inode) {
        ctx.ino = bprm->file->f_path.dentry->d_inode->i_ino;
        found_ino = true;
    }
    if (bprm->file->f_path.mnt->mnt_sb) {
        ctx.dev = bprm->file->f_path.mnt->mnt_sb->s_dev;
        found_dev = true;
    }
    if (!found_dev || !found_ino) {
        DS_LOG(DS_ERROR, " -- dynsec brpm_set_creds getting attr on file path failed. ");
        return ret;
    }

    // DS_LOG(DS_VERBOSE, " -- dynsec brpm_set_creds invoked with exec on name[%s] by process pid[%d] running as user[%d] effective-user[%d] inode[%llu] on device[MAJOR(%d) MINOR(%d)]. ", bprm->filename, current->pid, current_uid().val, current_euid().val, ks.ino, MAJOR(ks.dev), MINOR(ks.dev));
    ctx.op = OPC_OP_EXEC;
    ctx.pid = current->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    ctx.uid = current_uid().val;
    ctx.euid = current_euid().val;
    ctx.dentry = file_dentry(bprm->file);
#else
    ctx.uid = current_uid();
    ctx.euid = current_euid();
    ctx.dentry = bprm->file->f_path.dentry;
#endif
 
    if (OPC_RESULT_ALLOWED != opcache_is_op_allowed(&ctx)) {
        ret = -EPERM;
    }
#endif

out:

    return ret;
}

static int __init dynsec_init(void)
{
//    int ret = 0;
    DS_LOG(DS_INFO, "Initializing Dynamic Security Module Brand(%s)", CB_APP_MODULE_NAME);

    if (!dynsec_sym_init()) {
        return -EINVAL;
    }

    if (!dynsec_chrdev_init()) {
        return -EINVAL;
    }

    // ret = usercomm_init();
    // if (ret) {
    //     DS_LOG(DS_ERROR, "Unable to initialize usercomm.");
    //     return ret;
    // }
    
    // ret = opcache_init();
    // if (ret) {
    //     DS_LOG(DS_ERROR, "Unable to initialize opcache.");
    //     return ret;
    // }

    if (!dynsec_init_lsmhooks(DYNSEC_LSM_default)) {
        return -EINVAL;
    }

    return 0;
}

static void __exit dynsec_exit(void)
{

    DS_LOG(DS_INFO, "Exiting Dynamic Security Module Brand(%s)", CB_APP_MODULE_NAME);

    dynsec_lsm_shutdown();

    dynsec_chrdev_shutdown();
    
    // opcache_exit();
    
    // usercomm_exit();
}

module_init(dynsec_init);
module_exit(dynsec_exit);
