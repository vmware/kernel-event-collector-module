// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 VMware, Inc. All rights reserved.

// File is intented to support kernels with CONFIG_SECURITY_PATH enabled.
// Allows for a mostly safe kernel module unloading experience.

#ifdef CONFIG_SECURITY_PATH
#include <linux/version.h>
#include <linux/uidgid.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>

#include "factory.h"
#include "stall_tbl.h"
#include "stall_reqs.h"
#include "fs_utils.h"

// It is unknown how stable GFP_KERNEL would be for these hooks.
// BPF LSM functions don't let these hooks sleep. Rules can be
// broken, so we will try to follow those rules as a best effort.

int dynsec_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode,
                      unsigned int dev)
{
    umode_t local_mode;
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }

    if (!__is_client_concerned_filesystem(__path_sb(dir))) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_CREATE, GFP_ATOMIC);
        return 0;
    }

    local_mode = mode;
    if (!(local_mode & S_IFMT)) {
        local_mode |= S_IFREG;
    }
    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    if (S_ISREG(local_mode)) {
        event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_CREATE,
                                   DYNSEC_HOOK_TYPE_CREATE,
                                   report_flags, GFP_ATOMIC);
        if (!fill_in_path_create(event, dir, dentry, local_mode)) {
            prepare_non_report_event(DYNSEC_EVENT_TYPE_CREATE, GFP_ATOMIC);
            free_dynsec_event(event);
            return 0;
        }
        prepare_dynsec_event(event, GFP_ATOMIC);
        enqueue_nonstall_event(stall_tbl, event);
    } else {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_CREATE, GFP_ATOMIC);
    }

    return 0;
}

int dynsec_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }
    if (!__is_client_concerned_filesystem(__path_sb(dir))) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_MKDIR, GFP_ATOMIC);
        return 0;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }
    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_MKDIR,
                               DYNSEC_HOOK_TYPE_MKDIR,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_path_mkdir(event, dir, dentry, mode)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_MKDIR, GFP_ATOMIC);
        free_dynsec_event(event);
        return 0;
    }
    prepare_dynsec_event(event, GFP_ATOMIC);
    enqueue_nonstall_event(stall_tbl, event);

    return 0;
}

int dynsec_path_rmdir(const struct path *dir, struct dentry *dentry)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }
    if (!__is_client_concerned_filesystem(__path_sb(dir))) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_RMDIR, GFP_ATOMIC);
        return 0;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }
    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_RMDIR,
                               DYNSEC_HOOK_TYPE_RMDIR,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_path_rmdir(event, dir, dentry)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_RMDIR, GFP_ATOMIC);
        free_dynsec_event(event);
        return 0;
    }
    prepare_dynsec_event(event, GFP_ATOMIC);
    enqueue_nonstall_event(stall_tbl, event);

    return 0;
}

int dynsec_path_unlink(const struct path *dir, struct dentry *dentry)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }
    if (!__is_client_concerned_filesystem(__path_sb(dir))) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_UNLINK, GFP_ATOMIC);
        return 0;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }
    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_UNLINK,
                               DYNSEC_HOOK_TYPE_UNLINK,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_path_unlink(event, dir, dentry)) {
        prepare_non_report_event(DYNSEC_HOOK_TYPE_UNLINK, GFP_ATOMIC);
        free_dynsec_event(event);
        return 0;
    }
    prepare_dynsec_event(event, GFP_ATOMIC);
    enqueue_nonstall_event(stall_tbl, event);

    return 0;
}

int dynsec_path_symlink(const struct path *dir, struct dentry *dentry,
                        const char *old_name)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }
    if (!__is_client_concerned_filesystem(__path_sb(dir))) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SYMLINK, GFP_ATOMIC);
        return 0;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }
    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_SYMLINK,
                               DYNSEC_HOOK_TYPE_SYMLINK,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_path_symlink(event, dir, dentry, old_name)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SYMLINK, GFP_ATOMIC);
        free_dynsec_event(event);
        return 0;
    }
    prepare_dynsec_event(event, GFP_ATOMIC);
    enqueue_nonstall_event(stall_tbl, event);
    return 0;
}

int dynsec_path_link(struct dentry *old_dentry, const struct path *new_dir,
                     struct dentry *new_dentry)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }
    if (!__is_client_concerned_filesystem(__path_sb(new_dir))) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_LINK, GFP_ATOMIC);
        return 0;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }
    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_LINK,
                               DYNSEC_HOOK_TYPE_LINK,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_path_link(event, old_dentry, new_dir, new_dentry)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_LINK, GFP_ATOMIC);
        free_dynsec_event(event);
        return 0;
    }

    prepare_dynsec_event(event, GFP_ATOMIC);
    enqueue_nonstall_event(stall_tbl, event);
    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
int dynsec_path_rename(const struct path *old_dir, struct dentry *old_dentry,
                       const struct path *new_dir, struct dentry *new_dentry)
#else
int dynsec_path_rename(const struct path *old_dir, struct dentry *old_dentry,
                       const struct path *new_dir, struct dentry *new_dentry,
                       unsigned int flags)
#endif
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }
    if (!__is_client_concerned_filesystem(__path_sb(old_dir))) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_RENAME, GFP_ATOMIC);
        return 0;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }
    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_RENAME,
                               DYNSEC_HOOK_TYPE_RENAME,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_path_rename(event, old_dir, old_dentry,
                             new_dir, new_dentry)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_RENAME, GFP_ATOMIC);
        free_dynsec_event(event);
        return 0;
    }

    prepare_dynsec_event(event, GFP_ATOMIC);
    enqueue_nonstall_event(stall_tbl, event);
    return 0;
}

int dynsec_path_truncate(const struct path *path)
{
    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }

    // Determine if this hook is needed as an intent
    prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);

    return 0;
}

static int do_path_setattr(const struct path *path, const struct iattr *iattr)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_SETATTR,
                               DYNSEC_EVENT_TYPE_SETATTR,
                               report_flags, GFP_ATOMIC);
    if (!fill_in_path_setattr(event, path, iattr)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);
        free_dynsec_event(event);
        return 0;
    }

    prepare_dynsec_event(event, GFP_ATOMIC);
    enqueue_nonstall_event(stall_tbl, event);

    return 0;
}

int dynsec_path_chmod(const struct path *path, umode_t mode)
{
    struct iattr iattr;
    const struct inode *inode;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }
    if (!__is_client_concerned_filesystem(__path_sb(path))) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);
        return 0;
    }

    memset(&iattr, 0, sizeof(iattr));
    iattr.ia_valid = ATTR_MODE;
    iattr.ia_mode = mode;

    inode = __path_inode(path);
    if (inode) {
        iattr.ia_mode |= (S_IFMT & inode->i_mode);
    }

    return do_path_setattr(path, &iattr);
}

int dynsec_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
    struct iattr iattr;
    const struct inode *inode;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }
    if (!__is_client_concerned_filesystem(__path_sb(path))) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);
        return 0;
    }

    inode = __path_inode(path);
    if (!inode) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);
        return 0;
    }

    memset(&iattr, 0, sizeof(iattr));

    if (uid_eq(inode->i_uid, uid)) {
        iattr.ia_valid |= ATTR_UID;
        iattr.ia_uid = uid;
    }
    if (gid_eq(inode->i_gid, gid)) {
        iattr.ia_valid |= ATTR_GID;
        iattr.ia_gid = gid;
    }
    // Don't report if nothing changed
    if (!iattr.ia_valid) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);
        return 0;
    }
    return do_path_setattr(path, &iattr);
}

#endif /* CONFIG_SECURITY_PATH */
