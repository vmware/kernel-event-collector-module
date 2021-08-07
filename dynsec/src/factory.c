// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/dcache.h>

#include "dynsec.h"
#include "factory.h"
#include "path_utils.h"

// Set hook types to disable DYNSEC_REPORT_STALL aka observe timeouts
uint32_t debug_disable_stall_mask = 0;

static atomic64_t req_id = ATOMIC64_INIT(0);

static uint64_t dynsec_next_req_id(void)
{
    return atomic64_inc_return(&req_id);
}

static void init_dynsec_event(enum dynsec_event_type event_type, struct dynsec_event *event)
{
    if (event) {
        event->tid = current->pid;
        event->req_id = dynsec_next_req_id();
        event->event_type = event_type;
        INIT_LIST_HEAD(&event->list);
    }
}

// Helpers to set and unset report_flags as needed
#define init_event_report_flags(SUBEVENT, REPORT_FLAGS) \
    do { \
        SUBEVENT->kmsg.hdr.report_flags = (REPORT_FLAGS);\
        SUBEVENT->event.report_flags = SUBEVENT->kmsg.hdr.report_flags;\
    } while (0)

#define set_event_report_flags(SUBEVENT, REPORT_MASK) \
    do { \
        SUBEVENT->kmsg.hdr.report_flags |= (REPORT_MASK);\
        SUBEVENT->event.report_flags |= SUBEVENT->kmsg.hdr.report_flags;\
    } while (0)

#define unset_event_report_flags(SUBEVENT, REPORT_MASK) \
    do { \
        SUBEVENT->kmsg.hdr.report_flags &= (REPORT_MASK);\
        SUBEVENT->event.report_flags = SUBEVENT->kmsg.hdr.report_flags;\
    } while (0)

#define init_event_data(EVENT_TYPE, EVENT, REPORT_FLAGS, HOOK) \
    do { \
        init_dynsec_event(EVENT_TYPE, &EVENT->event);\
        init_event_report_flags(EVENT, REPORT_FLAGS);\
        EVENT->kmsg.hdr.hook_type = HOOK;\
        EVENT->kmsg.hdr.req_id = EVENT->event.req_id;\
        EVENT->kmsg.hdr.event_type = EVENT->event.event_type;\
        EVENT->kmsg.hdr.tid = EVENT->event.tid;\
        if (EVENT->kmsg.hdr.hook_type & debug_disable_stall_mask)\
            unset_event_report_flags(EVENT, ~(DYNSEC_REPORT_STALL));\
    } while (0)


static struct dynsec_event *alloc_exec_event(enum dynsec_event_type event_type,
                                             uint32_t hook_type, uint16_t report_flags,
                                             gfp_t mode)
{
    struct dynsec_exec_event *exec = kzalloc(sizeof(*exec), mode);

    if (!exec) {
        return NULL;
    }

    init_event_data(event_type, exec, report_flags, hook_type);

    return &exec->event;
}

static struct dynsec_event *alloc_unlink_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_unlink_event *unlink = kzalloc(sizeof(*unlink), mode);

    if (!unlink) {
        return NULL;
    }

    init_event_data(event_type, unlink, report_flags, hook_type);

    return &unlink->event;
}

static struct dynsec_event *alloc_rmdir_event(enum dynsec_event_type event_type,
                                              uint32_t hook_type, uint16_t report_flags,
                                              gfp_t mode)
{
    struct dynsec_unlink_event *rmdir = kzalloc(sizeof(*rmdir), mode);

    if (!rmdir) {
        return NULL;
    }

    init_event_data(event_type, rmdir, report_flags, hook_type);

    return &rmdir->event;
}

static struct dynsec_event *alloc_rename_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_rename_event *rename = kzalloc(sizeof(*rename), mode);

    if (!rename) {
        return NULL;
    }

    init_event_data(event_type, rename, report_flags, hook_type);

    return &rename->event;
}

static struct dynsec_event *alloc_setattr_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_setattr_event *setattr = kzalloc(sizeof(*setattr), mode);

    if (!setattr) {
        return NULL;
    }

    init_event_data(event_type, setattr, report_flags, hook_type);

    return &setattr->event;
}

static struct dynsec_event *alloc_create_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_create_event *create = kzalloc(sizeof(*create), mode);

    if (!create) {
        return NULL;
    }

    init_event_data(event_type, create, report_flags, hook_type);

    return &create->event;
}

static struct dynsec_event *alloc_file_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_file_event *file = kzalloc(sizeof(*file), mode);

    if (!file) {
        return NULL;
    }

    init_event_data(event_type, file, report_flags, hook_type);

    return &file->event;
}

// Event allocation factory
struct dynsec_event *alloc_dynsec_event(enum dynsec_event_type event_type,
                                        uint32_t hook_type,
                                        uint16_t report_flags,
                                        gfp_t mode)
{
    switch (event_type)
    {
    case DYNSEC_EVENT_TYPE_EXEC:
        return alloc_exec_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_UNLINK:
        return alloc_unlink_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_RMDIR:
        return alloc_rmdir_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_RENAME:
        return alloc_rename_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_SETATTR:
        return alloc_setattr_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_CREATE:
    case DYNSEC_EVENT_TYPE_MKDIR:
        return alloc_create_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_OPEN:
    case DYNSEC_EVENT_TYPE_CLOSE:
        return alloc_file_event(event_type, hook_type, report_flags, mode);

    default:
        break;
    }
    return NULL;
}

// Free events factory
void free_dynsec_event(struct dynsec_event *dynsec_event)
{
    if (!dynsec_event) {
        return;
    }

    switch (dynsec_event->event_type)
    {
    case DYNSEC_EVENT_TYPE_EXEC:
        {
            struct dynsec_exec_event *exec =
                    dynsec_event_to_exec(dynsec_event);

            kfree(exec->path);
            exec->path = NULL;
            kfree(exec);
        }
        break;

    case DYNSEC_EVENT_TYPE_RMDIR:
    case DYNSEC_EVENT_TYPE_UNLINK:
        {
            struct dynsec_unlink_event *unlink =
                    dynsec_event_to_unlink(dynsec_event);

            kfree(unlink->path);
            unlink->path = NULL;
            kfree(unlink);
        }
        break;

    case DYNSEC_EVENT_TYPE_RENAME:
        {
            struct dynsec_rename_event *rename =
                    dynsec_event_to_rename(dynsec_event);

            kfree(rename->old_path);
            rename->old_path = NULL;
            kfree(rename->new_path);
            rename->new_path = NULL;
            kfree(rename);
        }
        break;

    case DYNSEC_EVENT_TYPE_SETATTR:
        {
            struct dynsec_setattr_event *setattr =
                    dynsec_event_to_setattr(dynsec_event);

            kfree(setattr->path);
            setattr->path = NULL;
            kfree(setattr);
        }
        break;

    case DYNSEC_EVENT_TYPE_CREATE:
    case DYNSEC_EVENT_TYPE_MKDIR:
        {
            struct dynsec_create_event *create =
                    dynsec_event_to_create(dynsec_event);

            kfree(create->path);
            create->path = NULL;
            kfree(create);
        }
        break;

    case DYNSEC_EVENT_TYPE_OPEN:
    case DYNSEC_EVENT_TYPE_CLOSE:
        {
            struct dynsec_file_event *file =
                    dynsec_event_to_file(dynsec_event);

            kfree(file->path);
            file->path = NULL;
            kfree(file);
        }
        break;

    default:
        break;
    }
}

// Every event should first copy struct dynsec_msg_hdr followed by
// whatever extra fields and structs.
uint16_t get_dynsec_event_payload(struct dynsec_event *dynsec_event)
{
    if (!dynsec_event) {
        return 0;
    }

    switch (dynsec_event->event_type)
    {
    case DYNSEC_EVENT_TYPE_EXEC:
        {
            struct dynsec_exec_event *exec =
                    dynsec_event_to_exec(dynsec_event);
            return exec->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_RMDIR:
    case DYNSEC_EVENT_TYPE_UNLINK:
        {
            struct dynsec_unlink_event *unlink =
                    dynsec_event_to_unlink(dynsec_event);
            return unlink->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_RENAME:
        {
            struct dynsec_rename_event *rename =
                    dynsec_event_to_rename(dynsec_event);
            return rename->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_SETATTR:
        {
            struct dynsec_setattr_event *setattr =
                    dynsec_event_to_setattr(dynsec_event);
            return setattr->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_CREATE:
    case DYNSEC_EVENT_TYPE_MKDIR:
        {
            struct dynsec_create_event *create =
                    dynsec_event_to_create(dynsec_event);
            return create->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_OPEN:
    case DYNSEC_EVENT_TYPE_CLOSE:
        {
            struct dynsec_file_event *file =
                    dynsec_event_to_file(dynsec_event);
            return file->kmsg.hdr.payload;
        }
        break;

    default:
        break;
    }
    return 0;
}


// Helper to copy_dynsec_event_to_user
// Copies:
//  - struct dynsec_msg_hdr
//  - struct dynsec_exec_msg
//  - null terminated filepath
static ssize_t copy_exec_event(const struct dynsec_exec_event *exec,
                               char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < exec->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &exec->kmsg, sizeof(exec->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(exec->kmsg);
        p += sizeof(exec->kmsg);
    }

    // Copy executed file
    if (exec->path && exec->kmsg.msg.file.path_offset &&
        exec->kmsg.msg.file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    exec->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, exec->path, exec->kmsg.msg.file.path_size)) {
            goto out_fail;
        }  else {
            copied += exec->kmsg.msg.file.path_size;
        }
    }

    if (exec->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                exec->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

static ssize_t copy_unlink_event(const struct dynsec_unlink_event *unlink,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < unlink->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &unlink->kmsg, sizeof(unlink->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(unlink->kmsg);
        p += sizeof(unlink->kmsg);
    }

    // Copy Path Being Removed
    if (unlink->path && unlink->kmsg.msg.file.path_offset &&
        unlink->kmsg.msg.file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    unlink->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, unlink->path, unlink->kmsg.msg.file.path_size)) {
            goto out_fail;
        }  else {
            copied += unlink->kmsg.msg.file.path_size;
            p += unlink->kmsg.msg.file.path_size;
        }
    }

    if (unlink->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                unlink->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}


static ssize_t copy_rename_event(const struct dynsec_rename_event *rename,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < rename->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &rename->kmsg, sizeof(rename->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(rename->kmsg);
        p += sizeof(rename->kmsg);
    }

    // Copy Old Path
    if (rename->old_path && rename->kmsg.msg.old_file.path_offset &&
        rename->kmsg.msg.old_file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    rename->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, rename->old_path, rename->kmsg.msg.old_file.path_size)) {
            goto out_fail;
        }  else {
            copied += rename->kmsg.msg.old_file.path_size;
            p += rename->kmsg.msg.old_file.path_size;
        }
    }

    // Copy New Path
    if (rename->new_path && rename->kmsg.msg.new_file.path_offset &&
        rename->kmsg.msg.new_file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    rename->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, rename->new_path, rename->kmsg.msg.new_file.path_size)) {
            goto out_fail;
        }  else {
            copied += rename->kmsg.msg.new_file.path_size;
            p += rename->kmsg.msg.new_file.path_size;
        }
    }

    if (rename->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                rename->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

static ssize_t copy_create_event(const struct dynsec_create_event *create,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < create->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &create->kmsg, sizeof(create->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(create->kmsg);
        p += sizeof(create->kmsg);
    }

    // Copy Path Being Created
    if (create->path && create->kmsg.msg.file.path_offset &&
        create->kmsg.msg.file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    create->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, create->path, create->kmsg.msg.file.path_size)) {
            goto out_fail;
        }  else {
            copied += create->kmsg.msg.file.path_size;
            p += create->kmsg.msg.file.path_size;
        }
    }

    if (create->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                create->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}


static ssize_t copy_setattr_event(const struct dynsec_setattr_event *setattr,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < setattr->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &setattr->kmsg, sizeof(setattr->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(setattr->kmsg);
        p += sizeof(setattr->kmsg);
    }

    // Copy Old Path
    if (setattr->path && setattr->kmsg.msg.file.path_offset &&
        setattr->kmsg.msg.file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    setattr->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, setattr->path, setattr->kmsg.msg.file.path_size)) {
            goto out_fail;
        }  else {
            copied += setattr->kmsg.msg.file.path_size;
            p += setattr->kmsg.msg.file.path_size;
        }
    }

    if (setattr->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                setattr->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

static ssize_t copy_file_event(const struct dynsec_file_event *file,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < file->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &file->kmsg, sizeof(file->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(file->kmsg);
        p += sizeof(file->kmsg);
    }

    // TODO: Install fd If Desirable Feature

    // Copy Path Being Created
    if (file->path && file->kmsg.msg.file.path_offset &&
        file->kmsg.msg.file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    file->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, file->path, file->kmsg.msg.file.path_size)) {
            goto out_fail;
        } else {
            copied += file->kmsg.msg.file.path_size;
            p += file->kmsg.msg.file.path_size;
        }
    }

    if (file->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                file->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

// Copy to userspace
ssize_t copy_dynsec_event_to_user(const struct dynsec_event *dynsec_event,
                                  char *__user p, size_t count)
{
    if (!dynsec_event) {
        return -EINVAL;
    }

    // Copy might be different per event type
    switch (dynsec_event->event_type)
    {
    case DYNSEC_EVENT_TYPE_EXEC:
        {
            const struct dynsec_exec_event *exec =
                                    dynsec_event_to_exec(dynsec_event);
            return copy_exec_event(exec, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_RMDIR:
    case DYNSEC_EVENT_TYPE_UNLINK:
        {
            const struct dynsec_unlink_event *unlink =
                                    dynsec_event_to_unlink(dynsec_event);
            return copy_unlink_event(unlink, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_RENAME:
        {
            const struct dynsec_rename_event *rename =
                                    dynsec_event_to_rename(dynsec_event);
            return copy_rename_event(rename, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_SETATTR:
        {
            const struct dynsec_setattr_event *setattr =
                                    dynsec_event_to_setattr(dynsec_event);
            return copy_setattr_event(setattr, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_CREATE:
    case DYNSEC_EVENT_TYPE_MKDIR:
        {
            const struct dynsec_create_event *create =
                                    dynsec_event_to_create(dynsec_event);
            return copy_create_event(create, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_CLOSE:
    case DYNSEC_EVENT_TYPE_OPEN:
        {
            const struct dynsec_file_event *file =
                                    dynsec_event_to_file(dynsec_event);
            return copy_file_event(file, p, count);
        }
        break;

    default:
        break;
    }

    pr_info("%s: Invalid Event Type\n", __func__);
    return -EINVAL;
}

static void fill_in_task_ctx(struct dynsec_task_ctx *task_ctx)
{
    task_ctx->mnt_ns = get_mnt_ns_id(current);
    task_ctx->tid = current->pid;
    task_ctx->pid = current->tgid;
    if (current->real_parent) {
        task_ctx->ppid = current->real_parent->tgid;
    }

    // user DAC context
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    task_ctx->uid = from_kuid(&init_user_ns, current_uid());
    task_ctx->euid = from_kuid(&init_user_ns, current_euid());
    task_ctx->gid = from_kgid(&init_user_ns, current_gid());
    task_ctx->egid = from_kgid(&init_user_ns, current_egid());
#else
    task_ctx->uid = current_uid();
    task_ctx->euid = current_euid();
    task_ctx->gid = current_gid();
    task_ctx->egid = current_egid();
#endif

    task_ctx->flags = current->flags;
}

static void fill_in_sb_data(struct dynsec_file *dynsec_file, const struct super_block *sb)
{
    if (sb) {
        dynsec_file->dev = sb->s_dev;
        dynsec_file->sb_magic = sb->s_magic;
    }
}

static void fill_in_inode_data(struct dynsec_file *dynsec_file,
                                 const struct inode *inode)
{
    if (dynsec_file && inode) {
        dynsec_file->ino = inode->i_ino;
        dynsec_file->umode = inode->i_mode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        dynsec_file->uid = from_kuid(&init_user_ns, inode->i_uid);
        dynsec_file->gid = from_kgid(&init_user_ns, inode->i_gid);
#else
        dynsec_file->uid = inode->i_uid;
        dynsec_file->gid = inode->i_gid;
#endif
        dynsec_file->size = inode->i_size;
        fill_in_sb_data(dynsec_file, inode->i_sb);
    }
}

// dentry based callers may want to call dget_parent if sleepable
static void fill_in_parent_data(struct dynsec_file *dynsec_file,
                                struct inode *parent_dir)
{
    if (dynsec_file && parent_dir) {
        dynsec_file->parent_ino = parent_dir->i_ino;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        dynsec_file->parent_uid = from_kuid(&init_user_ns, parent_dir->i_uid);
        dynsec_file->parent_gid = from_kgid(&init_user_ns, parent_dir->i_gid);
#else
        dynsec_file->parent_uid = parent_dir->i_uid;
        dynsec_file->parent_gid = parent_dir->i_gid;
#endif
    }
}

static void fill_in_dentry_data(struct dynsec_file *dynsec_file,
                                  const struct dentry *dentry)
{
    if (dynsec_file && dentry) {
        fill_in_inode_data(dynsec_file, dentry->d_inode);
        fill_in_sb_data(dynsec_file, dentry->d_sb);
        if (dentry && dentry->d_parent && dentry != dentry->d_parent) {
            fill_in_parent_data(dynsec_file, dentry->d_parent->d_inode);
        }
    }
}

static void fill_in_file_data(struct dynsec_file *dynsec_file,
                              const struct path *path)
{
    // TODO: handle cross mountpoint parents?
    if (path && path->dentry) {
        fill_in_dentry_data(dynsec_file, path->dentry);
    }
    if (path && path->mnt) {
        fill_in_sb_data(dynsec_file, path->mnt->mnt_sb);
    }
}

// Fill in event data and compute payload
bool fill_in_bprm_set_creds(struct dynsec_event *dynsec_event,
                            const struct linux_binprm *bprm, gfp_t mode)
{
    struct dynsec_exec_event *exec = NULL;
    if (dynsec_event &&
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_EXEC) {
        return false;
    }

    exec = dynsec_event_to_exec(dynsec_event);

    exec->kmsg.hdr.payload = sizeof(exec->kmsg);
    fill_in_task_ctx(&exec->kmsg.msg.task);

    fill_in_file_data(&exec->kmsg.msg.file, &bprm->file->f_path);

    exec->path = dynsec_build_path(&bprm->file->f_path,
                                &exec->kmsg.msg.file.path_size,
                                GFP_KERNEL);
    if (exec->path && exec->kmsg.msg.file.path_size) {
        exec->kmsg.msg.file.path_offset = exec->kmsg.hdr.payload;
        exec->kmsg.hdr.payload += exec->kmsg.msg.file.path_size;
    }

    return true;
}

bool fill_in_inode_unlink(struct dynsec_event *dynsec_event,
                          struct inode *dir, struct dentry *dentry, gfp_t mode)
{
    struct dynsec_unlink_event *unlink = NULL;

    if (dynsec_event &&
        !(dynsec_event->event_type == DYNSEC_EVENT_TYPE_UNLINK ||
          dynsec_event->event_type == DYNSEC_EVENT_TYPE_RMDIR)) {
        return false;
    }
    unlink = dynsec_event_to_unlink(dynsec_event);

    unlink->kmsg.hdr.payload = sizeof(unlink->kmsg);
    fill_in_task_ctx(&unlink->kmsg.msg.task);

    fill_in_dentry_data(&unlink->kmsg.msg.file, dentry);
    fill_in_parent_data(&unlink->kmsg.msg.file, dir);

    unlink->path = dynsec_build_dentry(dentry,
                                &unlink->kmsg.msg.file.path_size,
                                mode);
    if (unlink->path && unlink->kmsg.msg.file.path_size) {
        unlink->kmsg.msg.file.path_offset = unlink->kmsg.hdr.payload;
        unlink->kmsg.hdr.payload += unlink->kmsg.msg.file.path_size;
    }

    return true;
}

bool fill_in_inode_rename(struct dynsec_event *dynsec_event,
                          struct inode *old_dir, struct dentry *old_dentry,
                          struct inode *new_dir, struct dentry *new_dentry,
                          gfp_t mode)
{
    struct dynsec_rename_event *rename = NULL;

    if (dynsec_event &&
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_RENAME) {
        return false;
    }
    rename = dynsec_event_to_rename(dynsec_event);

    rename->kmsg.hdr.payload = sizeof(rename->kmsg);
    fill_in_task_ctx(&rename->kmsg.msg.task);

    fill_in_dentry_data(&rename->kmsg.msg.old_file, old_dentry);
    fill_in_parent_data(&rename->kmsg.msg.old_file, old_dir);

    fill_in_dentry_data(&rename->kmsg.msg.new_file, new_dentry);
    fill_in_parent_data(&rename->kmsg.msg.new_file, new_dir);

    rename->old_path = dynsec_build_dentry(old_dentry,
                                &rename->kmsg.msg.old_file.path_size,
                                mode);
    if (rename->old_path && rename->kmsg.msg.old_file.path_size) {
        rename->kmsg.msg.old_file.path_offset = rename->kmsg.hdr.payload;
        rename->kmsg.hdr.payload += rename->kmsg.msg.old_file.path_size;
    }

    rename->new_path = dynsec_build_dentry(new_dentry,
                                &rename->kmsg.msg.new_file.path_size,
                                mode);
    if (rename->new_path && rename->kmsg.msg.new_file.path_size) {
        rename->kmsg.msg.new_file.path_offset = rename->kmsg.hdr.payload;
        rename->kmsg.hdr.payload += rename->kmsg.msg.new_file.path_size;
    }

    return true;
}

bool fill_in_inode_setattr(struct dynsec_event *dynsec_event,
                           unsigned int attr_mask, struct dentry *dentry,
                           struct iattr *attr, gfp_t mode)
{
    struct dynsec_setattr_event *setattr = NULL;

    if (dynsec_event &&
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_SETATTR) {
        return false;
    }
    setattr = dynsec_event_to_setattr(dynsec_event);

    setattr->kmsg.hdr.payload = sizeof(setattr->kmsg);

    fill_in_task_ctx(&setattr->kmsg.msg.task);

    // Tell user we got likely have a filepath
    if (attr_mask & ATTR_MODE) {
        setattr->kmsg.msg.attr_umode = attr->ia_mode;
    }
    if (attr_mask & ATTR_UID) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        setattr->kmsg.msg.attr_uid =
            from_kuid(&init_user_ns, attr->ia_uid);
#else
        setattr->kmsg.msg.attr_uid = attr->ia_uid;
#endif
    }
    if (attr_mask & ATTR_GID) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        setattr->kmsg.msg.attr_gid =
            from_kgid(&init_user_ns, attr->ia_gid);
#else
        setattr->kmsg.msg.attr_gid = attr->ia_gid;
#endif
    }
    if (attr_mask & ATTR_SIZE) {
        // Tells how was file change like open(O_CREAT) or truncate/fallocate
        attr_mask |= (attr->ia_valid & ATTR_OPEN);
        setattr->kmsg.msg.attr_size = attr->ia_size;
    }

    // Fill in file path related info
    if ((attr->ia_valid & ATTR_FILE) && attr->ia_file) {
        // Tells user this is the full filepath
        attr_mask |= ATTR_FILE;

        // dentry from provided ia_file is "new" dentry
        fill_in_file_data(&setattr->kmsg.msg.file, &attr->ia_file->f_path);
        // fill_in_dentry_data(&setattr->kmsg.msg.file, dentry);
        // if (attr->ia_file->f_path.mnt) {
        //     fill_in_sb_data(&setattr->kmsg.msg.file,
        //                     attr->ia_file->f_path.mnt->mnt_sb);
        // }
        setattr->path = dynsec_build_path(&attr->ia_file->f_path,
                                    &setattr->kmsg.msg.file.path_size,
                                    mode);
    } else {
        fill_in_dentry_data(&setattr->kmsg.msg.file, dentry);
        setattr->path = dynsec_build_dentry(dentry,
                                    &setattr->kmsg.msg.file.path_size,
                                    mode);
    }
    if (setattr->path && setattr->kmsg.msg.file.path_size) {
        setattr->kmsg.msg.file.path_offset = setattr->kmsg.hdr.payload;
        setattr->kmsg.hdr.payload += setattr->kmsg.msg.file.path_size;
    }

    setattr->kmsg.msg.attr_mask = attr_mask;

    return true;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
bool fill_in_inode_create(struct dynsec_event *dynsec_event,
                          struct inode *dir, struct dentry *dentry,
                          umode_t umode, gfp_t mode)
#else
bool fill_in_inode_create(struct dynsec_event *dynsec_event,
                          struct inode *dir, struct dentry *dentry,
                          int umode, gfp_t mode)
#endif
{
    struct dynsec_create_event *create = NULL;

    if (dynsec_event &&
        !(dynsec_event->event_type == DYNSEC_EVENT_TYPE_CREATE ||
          dynsec_event->event_type == DYNSEC_EVENT_TYPE_MKDIR)) {
        return false;
    }

    create = dynsec_event_to_create(dynsec_event);

    create->kmsg.hdr.payload = sizeof(create->kmsg);
    fill_in_task_ctx(&create->kmsg.msg.task);

    fill_in_dentry_data(&create->kmsg.msg.file, dentry);
    fill_in_parent_data(&create->kmsg.msg.file, dir);

    create->kmsg.msg.file.umode = (uint16_t)(umode & ~current_umask());
    if (dynsec_event->event_type == DYNSEC_EVENT_TYPE_MKDIR) {
        create->kmsg.msg.file.umode |= S_IFDIR;
    }

    create->path = dynsec_build_dentry(dentry,
                                &create->kmsg.msg.file.path_size,
                                mode);
    if (create->path && create->kmsg.msg.file.path_size) {
        create->kmsg.msg.file.path_offset = create->kmsg.hdr.payload;
        create->kmsg.hdr.payload += create->kmsg.msg.file.path_size;
    }

    return true;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
bool fill_in_inode_mkdir(struct dynsec_event *dynsec_event,
                         struct inode *dir, struct dentry *dentry,
                         umode_t umode, gfp_t mode)
#else
bool fill_in_inode_mkdir(struct dynsec_event *dynsec_event,
                         struct inode *dir, struct dentry *dentry,
                         int umode, gfp_t mode)
#endif
{
    return fill_in_inode_create(dynsec_event, dir, dentry, umode, mode);
}


extern bool fill_in_file_open(struct dynsec_event *dynsec_event, struct file *file,
                              gfp_t mode)
{
    struct dynsec_file_event *open = NULL;

    if (dynsec_event &&
        !(dynsec_event->event_type == DYNSEC_EVENT_TYPE_OPEN)) {
        return false;
    }

    open = dynsec_event_to_file(dynsec_event);
    open->kmsg.hdr.payload = sizeof(open->kmsg);

    fill_in_task_ctx(&open->kmsg.msg.task);
    open->kmsg.msg.f_mode = file->f_mode;
    open->kmsg.msg.f_flags = file->f_flags;
    fill_in_file_data(&open->kmsg.msg.file, &file->f_path);

    open->path = dynsec_build_path(&file->f_path, &open->kmsg.msg.file.path_size, mode);

    if (open->path && open->kmsg.msg.file.path_size) {
        open->kmsg.msg.file.path_offset = open->kmsg.hdr.payload;
        open->kmsg.hdr.payload += open->kmsg.msg.file.path_size;
    }

    return true;
}

extern bool fill_in_file_free(struct dynsec_event *dynsec_event, struct file *file,
                              gfp_t mode)
{
    struct dynsec_file_event *close = NULL;

    if (dynsec_event &&
        !(dynsec_event->event_type == DYNSEC_EVENT_TYPE_CLOSE)) {
        return false;
    }

    close = dynsec_event_to_file(dynsec_event);
    close->kmsg.hdr.payload = sizeof(close->kmsg);

    fill_in_task_ctx(&close->kmsg.msg.task);
    close->kmsg.msg.f_mode = file->f_mode;
    close->kmsg.msg.f_flags = file->f_flags;
    fill_in_file_data(&close->kmsg.msg.file, &file->f_path);

    // May want to provide dentry path
    close->path = dynsec_build_path(&file->f_path, &close->kmsg.msg.file.path_size, mode);

    if (close->path && close->kmsg.msg.file.path_size) {
        close->kmsg.msg.file.path_offset = close->kmsg.hdr.payload;
        close->kmsg.hdr.payload += close->kmsg.msg.file.path_size;
    }

    return true;
}
