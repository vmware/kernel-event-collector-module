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
    struct dynsec_exec_event *exec_event = kzalloc(sizeof(*exec_event), mode);

    if (!exec_event) {
        return NULL;
    }

    init_event_data(event_type, exec_event, report_flags, hook_type);

    return &exec_event->event;
}

static struct dynsec_event *alloc_unlink_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_unlink_event *unlink_event = kzalloc(sizeof(*unlink_event), mode);

    if (!unlink_event) {
        return NULL;
    }

    init_event_data(event_type, unlink_event, report_flags, hook_type);

    return &unlink_event->event;
}

static struct dynsec_event *alloc_rmdir_event(enum dynsec_event_type event_type,
                                              uint32_t hook_type, uint16_t report_flags,
                                              gfp_t mode)
{
    struct dynsec_unlink_event *rmdir_event = kzalloc(sizeof(*rmdir_event), mode);

    if (!rmdir_event) {
        return NULL;
    }

    init_event_data(event_type, rmdir_event, report_flags, hook_type);

    return &rmdir_event->event;
}

static struct dynsec_event *alloc_rename_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_rename_event *rename_event = kzalloc(sizeof(*rename_event), mode);

    if (!rename_event) {
        return NULL;
    }

    init_event_data(event_type, rename_event, report_flags, hook_type);

    return &rename_event->event;
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
            struct dynsec_exec_event *exec_event =
                    dynsec_event_to_exec(dynsec_event);

            if (exec_event->kmsg.path) {
                kfree(exec_event->kmsg.path);
                exec_event->kmsg.path = NULL;
            }
            kfree(exec_event);
        }
        break;

    case DYNSEC_EVENT_TYPE_RMDIR:
    case DYNSEC_EVENT_TYPE_UNLINK:
        {
            struct dynsec_unlink_event *unlink_event =
                    dynsec_event_to_unlink(dynsec_event);

            if (unlink_event->kmsg.path) {
                kfree(unlink_event->kmsg.path);
                unlink_event->kmsg.path = NULL;
            }
            kfree(unlink_event);
        }
        break;

    case DYNSEC_EVENT_TYPE_RENAME:
        {
            struct dynsec_rename_event *rename_event =
                    dynsec_event_to_rename(dynsec_event);

            if (rename_event->kmsg.old_path) {
                kfree(rename_event->kmsg.old_path);
                rename_event->kmsg.old_path = NULL;
            }
            if (rename_event->kmsg.new_path) {
                kfree(rename_event->kmsg.new_path);
                rename_event->kmsg.new_path = NULL;
            }
            kfree(rename_event);
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
            struct dynsec_exec_event *exec_event =
                    dynsec_event_to_exec(dynsec_event);
            return exec_event->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_RMDIR:
    case DYNSEC_EVENT_TYPE_UNLINK:
        {
            struct dynsec_unlink_event *unlink_event =
                    dynsec_event_to_unlink(dynsec_event);
            return unlink_event->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_RENAME:
        {
            struct dynsec_rename_event *rename_event =
                    dynsec_event_to_rename(dynsec_event);
            return rename_event->kmsg.hdr.payload;
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
static ssize_t copy_exec_event(const struct dynsec_exec_event *exec_event,
                               char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < exec_event->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &exec_event->kmsg.hdr, sizeof(exec_event->kmsg.hdr))) {
        goto out_fail;
    } else {
        copied += sizeof(exec_event->kmsg.hdr);
        p += sizeof(exec_event->kmsg.hdr);
    }

    // Copy exec event's static data
    if (copy_to_user(p, &exec_event->kmsg.msg, sizeof(exec_event->kmsg.msg))) {
        goto out_fail;
    } else {
        copied += sizeof(exec_event->kmsg.msg);
        p += sizeof(exec_event->kmsg.msg);
    }

    // Copy executed file
    if (exec_event->kmsg.path && exec_event->kmsg.msg.file.path_offset &&
        exec_event->kmsg.msg.file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    exec_event->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, exec_event->kmsg.path, exec_event->kmsg.msg.file.path_size)) {
            goto out_fail;
        }  else {
            copied += exec_event->kmsg.msg.file.path_size;
        }
    }

    if (exec_event->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                exec_event->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

static ssize_t copy_unlink_event(const struct dynsec_unlink_event *unlink_event,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < unlink_event->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &unlink_event->kmsg.hdr, sizeof(unlink_event->kmsg.hdr))) {
        goto out_fail;
    } else {
        copied += sizeof(unlink_event->kmsg.hdr);
        p += sizeof(unlink_event->kmsg.hdr);
    }

    // Copy exec event's static data
    if (copy_to_user(p, &unlink_event->kmsg.msg, sizeof(unlink_event->kmsg.msg))) {
        goto out_fail;
    } else {
        copied += sizeof(unlink_event->kmsg.msg);
        p += sizeof(unlink_event->kmsg.msg);
    }

    // Copy Path Being Removed
    if (unlink_event->kmsg.path && unlink_event->kmsg.msg.file.path_offset &&
        unlink_event->kmsg.msg.file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    unlink_event->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, unlink_event->kmsg.path, unlink_event->kmsg.msg.file.path_size)) {
            goto out_fail;
        }  else {
            copied += unlink_event->kmsg.msg.file.path_size;
        }
    }

    if (unlink_event->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                unlink_event->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}


static ssize_t copy_rename_event(const struct dynsec_rename_event *rename_event,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < rename_event->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &rename_event->kmsg.hdr, sizeof(rename_event->kmsg.hdr))) {
        goto out_fail;
    } else {
        copied += sizeof(rename_event->kmsg.hdr);
        p += sizeof(rename_event->kmsg.hdr);
    }

    // Copy exec event's static data
    if (copy_to_user(p, &rename_event->kmsg.msg, sizeof(rename_event->kmsg.msg))) {
        goto out_fail;
    } else {
        copied += sizeof(rename_event->kmsg.msg);
        p += sizeof(rename_event->kmsg.msg);
    }

    // Copy Old Path
    if (rename_event->kmsg.old_path && rename_event->kmsg.msg.old_file.path_offset &&
        rename_event->kmsg.msg.old_file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    rename_event->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, rename_event->kmsg.old_path, rename_event->kmsg.msg.old_file.path_size)) {
            goto out_fail;
        }  else {
            copied += rename_event->kmsg.msg.old_file.path_size;
            p += rename_event->kmsg.msg.old_file.path_size;
        }
    }

    // Copy New Path
    if (rename_event->kmsg.new_path && rename_event->kmsg.msg.new_file.path_offset &&
        rename_event->kmsg.msg.new_file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    rename_event->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, rename_event->kmsg.new_path, rename_event->kmsg.msg.new_file.path_size)) {
            goto out_fail;
        }  else {
            copied += rename_event->kmsg.msg.new_file.path_size;
            p += rename_event->kmsg.msg.new_file.path_size;
        }
    }

    if (rename_event->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                rename_event->kmsg.hdr.payload, copied);
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
            const struct dynsec_exec_event *dee =
                                    dynsec_event_to_exec(dynsec_event);
            return copy_exec_event(dee, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_RMDIR:
    case DYNSEC_EVENT_TYPE_UNLINK:
        {
            const struct dynsec_unlink_event *unlink_event =
                                    dynsec_event_to_unlink(dynsec_event);
            return copy_unlink_event(unlink_event, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_RENAME:
        {
            const struct dynsec_rename_event *rename_event =
                                    dynsec_event_to_rename(dynsec_event);
            return copy_rename_event(rename_event, p, count);
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

    task_ctx->mnt_ns = get_mnt_ns_id(current);
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
        dynsec_file->uid = from_kgid(&init_user_ns, inode->i_gid);
#else
        dynsec_file->uid = inode->i_uid;
        dynsec_file->uid = inode->i_gid;
#endif
        fill_in_sb_data(dynsec_file, inode->i_sb);
    }
}

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
    if (path->dentry) {
        fill_in_dentry_data(dynsec_file, path->dentry);
    }
    if (path->mnt) {
        fill_in_sb_data(dynsec_file, path->mnt->mnt_sb);
    }
}

// Fill in event data and compute payload
bool fill_in_bprm_set_creds(struct dynsec_exec_event *exec_event,
                            const struct linux_binprm *bprm, gfp_t mode)
{
    if (!exec_event || !bprm) {
        return false;
    }

    exec_event->kmsg.hdr.payload = sizeof(exec_event->kmsg.hdr);

    fill_in_task_ctx(&exec_event->kmsg.msg.task);

    exec_event->kmsg.hdr.payload += sizeof(exec_event->kmsg.msg);


    fill_in_file_data(&exec_event->kmsg.msg.file, &bprm->file->f_path);

    exec_event->kmsg.path = dynsec_build_path(&bprm->file->f_path,
                                &exec_event->kmsg.msg.file.path_size,
                                GFP_KERNEL);
    if (exec_event->kmsg.path && exec_event->kmsg.msg.file.path_size) {
        exec_event->kmsg.msg.file.path_offset = exec_event->kmsg.hdr.payload;
        exec_event->kmsg.hdr.payload += exec_event->kmsg.msg.file.path_size;
    }

    return true;
}

bool fill_in_inode_unlink(struct dynsec_unlink_event *unlink_event,
                          struct inode *dir, struct dentry *dentry, gfp_t mode)
{
    // bool found_ino = false;
    // bool found_dev = false;

    if (!unlink_event || !dentry) {
        return false;
    }

    unlink_event->kmsg.hdr.payload = sizeof(unlink_event->kmsg.hdr);

    fill_in_task_ctx(&unlink_event->kmsg.msg.task);

    unlink_event->kmsg.hdr.payload += sizeof(unlink_event->kmsg.msg);

    fill_in_dentry_data(&unlink_event->kmsg.msg.file, dentry);
    fill_in_parent_data(&unlink_event->kmsg.msg.file, dir);

    unlink_event->kmsg.path = dynsec_build_dentry(dentry,
                                &unlink_event->kmsg.msg.file.path_size,
                                mode);
    if (unlink_event->kmsg.path && unlink_event->kmsg.msg.file.path_size) {
        unlink_event->kmsg.msg.file.path_offset = unlink_event->kmsg.hdr.payload;
        unlink_event->kmsg.hdr.payload += unlink_event->kmsg.msg.file.path_size;
    }

    return true;
}

bool fill_in_inode_rename(struct dynsec_rename_event *rename_event,
                          struct inode *old_dir, struct dentry *old_dentry,
                          struct inode *new_dir, struct dentry *new_dentry,
                          gfp_t mode)
{
    if (!rename_event || !old_dentry) {
        return false;
    }

    rename_event->kmsg.hdr.payload = sizeof(rename_event->kmsg.hdr);

    fill_in_task_ctx(&rename_event->kmsg.msg.task);

    rename_event->kmsg.hdr.payload += sizeof(rename_event->kmsg.msg);

    fill_in_dentry_data(&rename_event->kmsg.msg.old_file, old_dentry);
    fill_in_parent_data(&rename_event->kmsg.msg.old_file, old_dir);

    fill_in_dentry_data(&rename_event->kmsg.msg.new_file, new_dentry);
    fill_in_parent_data(&rename_event->kmsg.msg.new_file, new_dir);

    rename_event->kmsg.old_path = dynsec_build_dentry(old_dentry,
                                &rename_event->kmsg.msg.old_file.path_size,
                                mode);
    if (rename_event->kmsg.old_path && rename_event->kmsg.msg.old_file.path_size) {
        rename_event->kmsg.msg.old_file.path_offset = rename_event->kmsg.hdr.payload;
        rename_event->kmsg.hdr.payload += rename_event->kmsg.msg.old_file.path_size;
    }

    rename_event->kmsg.new_path = dynsec_build_dentry(new_dentry,
                                &rename_event->kmsg.msg.new_file.path_size,
                                mode);
    if (rename_event->kmsg.new_path && rename_event->kmsg.msg.new_file.path_size) {
        rename_event->kmsg.msg.new_file.path_offset = rename_event->kmsg.hdr.payload;
        rename_event->kmsg.hdr.payload += rename_event->kmsg.msg.new_file.path_size;
    }

    return true;
}
