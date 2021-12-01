// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include "dynsec.h"
#include "factory.h"
#include "stall_tbl.h"
#include "stall_reqs.h"
#include "lsm_mask.h"
#include "inode_cache.h"
#include "task_cache.h"
#include "task_utils.h"
#include "symbols.h"
#include "config.h"

int dynsec_bprm_set_creds(struct linux_binprm *bprm)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

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

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    } else {
        report_flags |= DYNSEC_REPORT_STALL;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_EXEC, DYNSEC_HOOK_TYPE_EXEC,
                               report_flags, GFP_KERNEL);
    if (!event) {
        goto out;
    }
    if (!fill_in_bprm_set_creds(event, bprm, GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_KERNEL);

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    return ret;
}

int dynsec_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;
    umode_t mode;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->inode_unlink(dir, dentry);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    } else {
        report_flags |= DYNSEC_REPORT_STALL;
    }

    // Only care about certain types of files
    if (!dentry->d_inode) {
        goto out;
    }
    mode = dentry->d_inode->i_mode;
    if (!(S_ISLNK(mode) || S_ISREG(mode) || S_ISDIR(mode))) {
        goto out;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_UNLINK, DYNSEC_HOOK_TYPE_UNLINK,
                               report_flags, GFP_KERNEL);
    if (!event) {
        goto out;
    }

    if (!fill_in_inode_unlink(event, dir, dentry, GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_KERNEL);

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    return ret;
}

int dynsec_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;
    umode_t mode;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->inode_rmdir(dir, dentry);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    } else {
        report_flags |= DYNSEC_REPORT_STALL;
    }

    // Only care about certain types of files
    if (!dentry->d_inode) {
        goto out;
    }
    mode = dentry->d_inode->i_mode;
    if (!(S_ISLNK(mode) || S_ISREG(mode) || S_ISDIR(mode))) {
        goto out;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_RMDIR, DYNSEC_HOOK_TYPE_RMDIR,
                               report_flags, GFP_KERNEL);
    if (!event) {
        goto out;
    }

    if (!fill_in_inode_unlink(event, dir, dentry, GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_KERNEL);

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    return ret;
}

int dynsec_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                        struct inode *new_dir, struct dentry *new_dentry)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;
    umode_t mode;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->inode_rename(old_dir, old_dentry,
                                               new_dir, new_dentry);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    } else {
        report_flags |= DYNSEC_REPORT_STALL;
    }

    if (!old_dentry->d_inode) {
        goto out;
    }
    mode = old_dentry->d_inode->i_mode;
    if (!(S_ISLNK(mode) || S_ISREG(mode) || S_ISDIR(mode))) {
        goto out;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_RENAME, DYNSEC_HOOK_TYPE_RENAME,
                               report_flags, GFP_KERNEL);
    if (!event) {
        goto out;
    }

    if (!fill_in_inode_rename(event,
                              old_dir, old_dentry,
                              new_dir, new_dentry,
                              GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_KERNEL);

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    return ret;
}

int dynsec_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;
    unsigned int attr_mask;

    BUILD_BUG_ON(DYNSEC_SETATTR_MODE != ATTR_MODE);
    BUILD_BUG_ON(DYNSEC_SETATTR_UID  != ATTR_UID);
    BUILD_BUG_ON(DYNSEC_SETATTR_GID  != ATTR_GID);
    BUILD_BUG_ON(DYNSEC_SETATTR_SIZE != ATTR_SIZE);
    BUILD_BUG_ON(DYNSEC_SETATTR_FILE != ATTR_FILE);
    BUILD_BUG_ON(DYNSEC_SETATTR_OPEN != ATTR_OPEN);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->inode_setattr(dentry, attr);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!dentry || !dentry->d_inode || !attr) {
        goto out;
    }

    attr_mask = attr->ia_valid;
    attr_mask &= (ATTR_MODE|ATTR_UID|ATTR_GID|ATTR_SIZE);

    if (!attr_mask) {
        goto out;
    }

    // Check for redundant fields
    if (attr_mask & ATTR_MODE) {
        // No need to check for subsets
        if (attr->ia_mode == dentry->d_inode->i_mode) {
            attr_mask &= ~(ATTR_MODE);
        }
    }
    if (attr_mask & ATTR_UID) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        if (uid_eq(attr->ia_uid, dentry->d_inode->i_uid))
#else
        if (attr->ia_uid == dentry->d_inode->i_uid)
#endif
        {
            attr_mask &= ~(ATTR_UID);
        }
    }
    if (attr_mask & ATTR_GID) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        if (gid_eq(attr->ia_gid, dentry->d_inode->i_gid))
#else
        if (attr->ia_gid == dentry->d_inode->i_gid)
#endif
        {
            attr_mask &= ~(ATTR_GID);
        }
    }
    if (attr_mask & ATTR_SIZE) {
        // Don't care about fallocate
        if (attr->ia_size) {
            attr_mask &= ~(ATTR_SIZE);
        }

        // Don't care if the file is already empty/truncated
        else if (attr->ia_size == dentry->d_inode->i_size) {
            attr_mask &= ~(ATTR_SIZE);
        }
    }

    if (!attr_mask) {
        goto out;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    } else {
        report_flags |= DYNSEC_REPORT_STALL;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_SETATTR, DYNSEC_HOOK_TYPE_SETATTR,
                               report_flags, GFP_KERNEL);

    if (!fill_in_inode_setattr(event, attr_mask,
                               dentry, attr, GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_KERNEL);

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
int dynsec_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
#else
int dynsec_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
#endif
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->inode_mkdir(dir, dentry, mode);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    } else {
        report_flags |= DYNSEC_REPORT_STALL;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_MKDIR, DYNSEC_HOOK_TYPE_MKDIR,
                               report_flags, GFP_KERNEL);
    if (!fill_in_inode_mkdir(event, dir, dentry, mode, GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_KERNEL);

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
int dynsec_inode_create(struct inode *dir, struct dentry *dentry,
                        umode_t mode)
#else
int dynsec_inode_create(struct inode *dir, struct dentry *dentry,
                        int mode)
#endif
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->inode_create(dir, dentry, mode);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    } else {
        report_flags |= DYNSEC_REPORT_STALL;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_CREATE, DYNSEC_HOOK_TYPE_CREATE,
                               report_flags, GFP_KERNEL);
    if (!fill_in_inode_create(event, dir, dentry, mode, GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_KERNEL);

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    return ret;
}

int dynsec_inode_link(struct dentry *old_dentry, struct inode *dir,
                      struct dentry *new_dentry)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->inode_link(old_dentry, dir, new_dentry);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    } else {
        report_flags |= DYNSEC_REPORT_STALL;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_LINK, DYNSEC_HOOK_TYPE_LINK,
                               report_flags, GFP_KERNEL);
    if (!fill_in_inode_link(event, old_dentry, dir, new_dentry, GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_KERNEL);

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    return ret;
}

int dynsec_inode_symlink(struct inode *dir, struct dentry *dentry,
                const char *old_name)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret =  g_original_ops_ptr->inode_symlink(dir, dentry, old_name);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    } else {
        report_flags |= DYNSEC_REPORT_STALL;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_SYMLINK, DYNSEC_HOOK_TYPE_SYMLINK,
                               report_flags, GFP_KERNEL);
    if (!fill_in_inode_symlink(event, dir, dentry, old_name, GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_KERNEL);

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    return ret;
}


void dynsec_inode_free_security(struct inode *inode)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        g_original_ops_ptr->inode_free_security(inode);
    }
#endif
    (void)inode_cache_remove_entry((unsigned long)inode);
}

static inline const struct inode * __file_inode(const struct file *file)
{
    if (likely(file) && file->f_path.dentry) {
        return file->f_path.dentry->d_inode;
    }
    return NULL;
}

static inline bool may_report_file(const struct file *file)
{
    if (likely(file)) {
        unsigned int f_flags;
        const struct inode *inode = NULL;

#ifdef FMODE_STREAM
        // File cannot be safely opened
        if (file->f_mode & FMODE_STREAM) {
            return false;
        }
#endif
#ifdef FMODE_NONOTIFY
        // File opened indirectly like fanotify.
        // Used to help prevent feedback loops.
        if (file->f_mode & FMODE_NONOTIFY) {
            return false;
        }
#endif
        f_flags = file->f_flags;
#ifdef O_PATH
        if (f_flags & O_PATH) {
            return false;
        }
#endif
        if (f_flags & O_DIRECTORY) {
            return false;
        }

        inode = __file_inode(file);
        if (inode) {
            umode_t umode = inode->i_mode;
#ifdef special_file
            if (special_file(umode)) {
                return false;
            }
#endif /* special_file */
            if (!S_ISREG(umode)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

static inline bool may_report_file_open(const struct file *file)
{
    return may_report_file(file);
}
static inline bool may_report_file_close(const struct file *file)
{
    return may_report_file(file);
}
#ifdef FMODE_NONOTIFY
#define may_client_report_files() (true)
#else
#define may_client_report_files() (false)
#endif /* FMODE_NONOTIFY */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
int dynsec_file_open(struct file *file)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
int dynsec_file_open(struct file *file, const struct cred *cred)
#else
int dynsec_dentry_open(struct file *file, const struct cred *cred)
#endif
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    u64 hits = 0;
    unsigned long inode_addr = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    if (g_original_ops_ptr) {
        ret =  g_original_ops_ptr->dentry_open(file, cred);
        if (ret) {
            goto out;
        }
    }
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->file_open(file, cred);
        if (ret) {
            goto out;
        }
    }
#endif

    if (may_report_file_open(file)) {
        report_flags |= DYNSEC_REPORT_STALL;
        inode_addr = (unsigned long)__file_inode(file);
    } else {
        goto out;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        // Don't want to create feedback loop
        // on files we open/close from the client.
        if (!may_client_report_files()) {
            // goto out;
        }
        report_flags |= DYNSEC_REPORT_SELF;
        report_flags &= ~(DYNSEC_REPORT_STALL);
    }

    // Copy over the struct inode address to possibly track
    if (inode_addr) {
        // Attempt to remove an entry if opened for write
        // or we may want to mark it disabled?
        if (file->f_mode & FMODE_WRITE) {
            (void)inode_cache_remove_entry(inode_addr);
        }
        // Allow for potential tracking or updating
        else if ((report_flags & DYNSEC_REPORT_STALL) &&
                 (file->f_mode & FMODE_READ)) {
            int rc = inode_cache_lookup(inode_addr, &hits,
                                        true, GFP_KERNEL);

            // If hit count is zero we don't want to disable stalling
            if (rc == 0) {
                if (hits > 0) {
                    report_flags &= ~(DYNSEC_REPORT_STALL);
                    report_flags |= DYNSEC_REPORT_INODE_CACHED;
                    inode_addr = 0;
                }
            }
            // Only copy inode_addr over when we want to
            // let userspace possibly allow the file to be recached.
            else if (rc < 0 && rc != -ENOENT) {
                inode_addr = 0;
            }
        } else {
            inode_addr = 0;
        }
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_OPEN, DYNSEC_HOOK_TYPE_OPEN,
                               report_flags, GFP_KERNEL);
    if (event && inode_addr) {
        event->inode_addr = inode_addr;
    }
    if (!fill_in_file_open(event, file, GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_KERNEL);

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    return ret;
}

// Must Not Stall - Enable only for open events
void dynsec_file_free_security(struct file *file)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
    if (g_original_ops_ptr) {
        g_original_ops_ptr->file_free_security(file);
    }
#endif

    if (!may_report_file_close(file)) {
        return;
    }
    if (!stall_tbl_enabled(stall_tbl)) {
        return;
    }
    if (task_in_connected_tgid(current)) {
        // Don't want to create feedback loop
        // on files we open/close from the client.
        if (!may_client_report_files()) {
            // return;
        }
        report_flags |= DYNSEC_REPORT_SELF;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_CLOSE, DYNSEC_HOOK_TYPE_CLOSE,
                               report_flags, GFP_ATOMIC);

    if (!fill_in_file_free(event, file, GFP_ATOMIC)) {
        free_dynsec_event(event);
        return;
    }
    (void)enqueue_nonstall_event(stall_tbl, event);
}

int dynsec_ptrace_traceme(struct task_struct *parent)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->ptrace_traceme(parent);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_PTRACE, DYNSEC_HOOK_TYPE_PTRACE,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_ptrace(event, parent, current)) {
        free_dynsec_event(event);
        goto out;
    }
    prepare_dynsec_event(event, GFP_ATOMIC);

    (void)enqueue_nonstall_event(stall_tbl, event);

out:

    return ret;
}

int dynsec_ptrace_access_check(struct task_struct *child, unsigned int mode)
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->ptrace_access_check(child, mode);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!(mode & PTRACE_MODE_ATTACH)) {
        goto out;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    } else if (task_in_connected_tgid(child)) {
        // To prevent a feedback loop. Cache this context after first event.
        goto out;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_PTRACE, DYNSEC_HOOK_TYPE_PTRACE,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_ptrace(event, current, child)) {
        free_dynsec_event(event);
        goto out;
    }

    (void)enqueue_nonstall_event(stall_tbl, event);

out:

    return ret;
}

// Must Not Stall
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
#if RHEL_MAJOR == 8 && RHEL_MINOR == 0
int dynsec_task_kill(struct task_struct *p, struct siginfo *info,
                     int sig, const struct cred *cred)
#else
int dynsec_task_kill(struct task_struct *p, struct kernel_siginfo *info,
                     int sig, const struct cred *cred)
#endif
#else
int dynsec_task_kill(struct task_struct *p, struct siginfo *info,
                     int sig, u32 secid)
#endif
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->task_kill(p, info, sig, secid);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!sig) {
        goto out;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_SIGNAL, DYNSEC_HOOK_TYPE_SIGNAL,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_task_kill(event, p, sig)) {
        free_dynsec_event(event);
        goto out;
    }
    (void)enqueue_nonstall_event(stall_tbl, event);

out:

    return ret;
}

// Backup hook to wake_up_new_task due to start_time
// here being junk or the parent's start_time
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
void dynsec_sched_process_fork_tp(void *data, struct task_struct *parent,
                                  struct task_struct *child)
#else
void dynsec_sched_process_fork_tp(struct task_struct *parent,
                                  struct task_struct *child)
#endif
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

    if (!child) {
        return;
    }
    // Don't send thread events
    if (child->tgid != child->pid) {
        return;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        return;
    }
    if (task_in_connected_tgid(parent)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_CLONE, DYNSEC_TP_HOOK_TYPE_CLONE,
                               report_flags, GFP_ATOMIC);
    //
    if (!fill_in_clone(event, parent, child,
                       DYNSEC_TASK_IMPRECISE_START_TIME)) {
        free_dynsec_event(event);
        return;
    }
    (void)enqueue_nonstall_event(stall_tbl, event);
}

static void __dynsec_task_exit(struct task_struct *task,
                               uint32_t exit_hook_type,
                               gfp_t mode)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;

    if (!task) {
        return;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        return;
    }

    // Clear Entry
    task_cache_remove_entry(task->pid);

    // Don't send thread events
    if (task->tgid != task->pid) {
        return;
    }

    // The common exit event should have to be high priority
    // as the task free event is always last.
    if (exit_hook_type == DYNSEC_TP_HOOK_TYPE_EXIT) {
        report_flags |= DYNSEC_REPORT_LO_PRI;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_EXIT, exit_hook_type,
                               report_flags, mode);
    if (!fill_task_free(event, task)) {
        free_dynsec_event(event);
        return;
    }

    (void)enqueue_nonstall_event(stall_tbl, event);
}
void dynsec_task_free(struct task_struct *task, uint32_t exit_hook_type)
{
    __dynsec_task_exit(task, DYNSEC_HOOK_TYPE_TASK_FREE, GFP_ATOMIC);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
void dynsec_sched_process_exit_tp(void *data, struct task_struct *task)
#else
void dynsec_sched_process_exit_tp(struct task_struct *task)
#endif
{
    __dynsec_task_exit(task, DYNSEC_TP_HOOK_TYPE_EXIT, GFP_ATOMIC);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
void dynsec_sched_process_free_tp(void *data, struct task_struct *task)
#else
void dynsec_sched_process_free_tp(struct task_struct *task)
#endif
{
    __dynsec_task_exit(task, DYNSEC_HOOK_TYPE_TASK_FREE, GFP_ATOMIC);
}

// Settings to help control mmap event performance
int mmap_report_misc = 1;
int mmap_stall_misc = 0;
int mmap_stall_on_exec = 1;
int mmap_stall_on_ldso = 1;

//
//
//
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
int dynsec_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot,
                     unsigned long flags)
#else
int dynsec_file_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
                     unsigned long flags, unsigned long addr, unsigned long addr_only)
#endif
{
    struct dynsec_event *event = NULL;
    int ret = 0;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;
    unsigned long rm_inode_addr = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->file_mmap(file, reqprot, prot, flags, addr, addr_only);
        if (ret) {
            goto out;
        }
    }
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
    if (g_original_ops_ptr) {
        ret = g_original_ops_ptr->mmap_file(file, reqprot, prot, flags);
        if (ret) {
            goto out;
        }
    }
#endif

    if (!file) {
        goto out;
    }

    // // Remove read-only entry if PROT_WRITE requested
    // TODO: verify other mmap args to remove entry
    // if (prot & PROT_WRITE) {
    //     rm_inode_addr = (unsigned long)__file_inode(file);
    //     inode_cache_remove_entry(rm_inode_addr);
    // }

    if (!(prot & PROT_EXEC)) {
        goto out;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }

    if (current->in_execve ||
        (file && (file->f_mode & FMODE_EXEC) == FMODE_EXEC)) {
        unsigned long exec_flags = flags & (MAP_DENYWRITE | MAP_EXECUTABLE);

        if (mmap_stall_on_exec && exec_flags & MAP_EXECUTABLE) {
            report_flags |= DYNSEC_REPORT_STALL;
        }
        else if (mmap_stall_on_ldso) {
            report_flags |= DYNSEC_REPORT_STALL;
        }

        // High priority even if we're not stalling
        report_flags |= DYNSEC_REPORT_HI_PRI;
    }
    else {
        if (mmap_stall_misc) {
            report_flags |= DYNSEC_REPORT_STALL;
        } else if (!mmap_report_misc) {
            goto out;
        }
    }

    // Don't stall on ourself
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
        report_flags &= ~(DYNSEC_REPORT_STALL);
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_MMAP, DYNSEC_HOOK_TYPE_MMAP,
                               report_flags, GFP_KERNEL);
    if (!fill_in_file_mmap(event, file, prot, flags, GFP_KERNEL)) {
        free_dynsec_event(event);
        goto out;
    }

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        int response = 0;
        int rc = dynsec_wait_event_timeout(event, &response, 1000, GFP_KERNEL);

        if (!rc) {
            ret = response;
        }
    } else {
        (void)enqueue_nonstall_event(stall_tbl, event);
    }

out:

    // Remove read-only entry on denial if exists
    if (!rm_inode_addr &&
        (ret == -EPERM || ret == -EACCES)) {
        rm_inode_addr = (unsigned long)__file_inode(file);
        inode_cache_remove_entry(rm_inode_addr);
    }

    return ret;
}

struct kprobe;
// Primary hook for clone events
int dynsec_wake_up_new_task(struct kprobe *kprobe, struct pt_regs *regs)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT;
    DECL_ARG_1(struct task_struct *, p);

    if (!p) {
        goto out;
    }
    // Don't send thread events
    if (p->tgid != p->pid) {
        goto out;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        goto out;
    }
    if (task_in_connected_tgid(p->real_parent)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_CLONE, DYNSEC_TP_HOOK_TYPE_CLONE,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_clone(event, NULL, p, 0)) {
        free_dynsec_event(event);
        goto out;
    }

    (void)enqueue_nonstall_event(stall_tbl, event);

out:
    return 0;
}

int dynsec_task_dump_all(uint16_t opts, pid_t start_pid)
{
    struct dynsec_event *dynsec_event;
    pid_t pid = start_pid;
    pid_t last_sent = 0;
    int ret = 0;
    int err = 0;

    if (!may_iterate_tasks()) {
        return -EINVAL;
    }

    while (1) {
        struct task_struct *task = dynsec_get_next_task(opts, &pid);

        if (!task) {
            break;
        }
        pid += 1;

        // We could dump kthreads but perhaps as an explicit option
        if (task->flags & PF_KTHREAD) {
            put_task_struct(task);
            continue;
        }

        dynsec_event = fill_in_dynsec_task_dump(task, GFP_KERNEL);
        last_sent = task->pid;
        put_task_struct(task);
        if (!dynsec_event) {
            err = -ENOMEM;
            break;
        }
        if (!enqueue_nonstall_event(stall_tbl, dynsec_event)) {
            err = -EINVAL;
            break;
        }

        // Could be a lot of iterating so sleep when asked
        cond_resched();
    }

    if (err) {
        ret = err;
        goto out;
    }
    // Check if we found a task
    if (!last_sent) {
        ret = -ENOENT;
        goto out;
    }

    // Dummy Event.
    dynsec_event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_TASK_DUMP, 0,
                        DYNSEC_REPORT_AUDIT | DYNSEC_REPORT_LAST_TASK,
                        GFP_KERNEL);
    if (!dynsec_event) {
        ret = -ENOMEM;
        goto out;
    }
    if (!enqueue_nonstall_event(stall_tbl, dynsec_event)) {
        ret = -EINVAL;
    }

out:
    return ret;
}

ssize_t dynsec_task_dump_one(uint16_t opts, pid_t start_pid,
                             void __user *ubuf, size_t size)
{
    pid_t pid = start_pid;
    struct dynsec_event *dynsec_event;
    ssize_t ret = -ENOENT;

    if (!may_iterate_tasks() || !ubuf || !size) {
        return -EINVAL;
    }

    while (1) {
        struct task_struct *task = dynsec_get_next_task(opts, &pid);
        uint16_t payload;

        if (!task) {
            break;
        }
        pid += 1;

        // We could dump kthreads but perhaps as an explicit option
        if (task->flags & PF_KTHREAD) {
            put_task_struct(task);
            continue;
        }

        dynsec_event = fill_in_dynsec_task_dump(task, GFP_KERNEL);
        put_task_struct(task);

        if (!dynsec_event) {
            ret = -ENOMEM;
            break;
        }
        payload = get_dynsec_event_payload(dynsec_event);
        if (payload > size) {
            free_dynsec_event(dynsec_event);
            ret = -EFAULT;
            break;
        }

        ret = copy_dynsec_event_to_user(dynsec_event, ubuf, size);
        free_dynsec_event(dynsec_event);
        break;
    }

    return ret;
}

// int dynsec_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
// {
// #if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
//     if (g_original_ops_ptr) {
//         return g_original_ops_ptr->task_fix_setuid(new, old, flags);
//     }
// #endif

//     return 0;
// }
