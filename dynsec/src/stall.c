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

#include "dynsec.h"
#include "stall.h"
#include "path_utils.h"

static atomic64_t req_id = ATOMIC64_INIT(0);

uint64_t dynsec_next_req_id(void)
{
    return atomic64_inc_return(&req_id);
}

static struct dynsec_event *alloc_exec_event(gfp_t mode)
{
    struct dynsec_exec_event *exec_event = kzalloc(sizeof(*exec_event), mode);

    if (!exec_event) {
        return NULL;
    }

    // Set key core data
    exec_event->event.req_id = dynsec_next_req_id();
    exec_event->event.event_type = DYNSEC_EVENT_TYPE_EXEC;

    exec_event->kmsg.hdr.req_id = exec_event->event.req_id;
    exec_event->kmsg.hdr.event_type = exec_event->event.event_type;

    return &exec_event->event;
}

static struct dynsec_event *alloc_unlink_event(gfp_t mode)
{
    struct dynsec_exec_event *unlink_event = kzalloc(sizeof(*unlink_event), mode);

    if (!unlink_event) {
        return NULL;
    }

    // Set key core data
    unlink_event->event.req_id = dynsec_next_req_id();
    unlink_event->event.event_type = DYNSEC_EVENT_TYPE_UNLINK;

    unlink_event->kmsg.hdr.req_id = unlink_event->event.req_id;
    unlink_event->kmsg.hdr.event_type = unlink_event->event.event_type;

    return &unlink_event->event;
}

// Event allocation factory
struct dynsec_event *alloc_dynsec_event(uint32_t event_type, gfp_t mode)
{
    switch (event_type)
    {
    case DYNSEC_EVENT_TYPE_EXEC:
        return alloc_exec_event(mode);

    case DYNSEC_EVENT_TYPE_UNLINK:
        return alloc_unlink_event(mode);

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

    case DYNSEC_EVENT_TYPE_UNLINK:
        {
        {
            struct dynsec_unlink_event *unlink_event =
                    dynsec_event_to_unlink(dynsec_event);
            return unlink_event->kmsg.hdr.payload;
        }
        break;
        }

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
    if (exec_event->kmsg.path && exec_event->kmsg.msg.path_offset &&
        exec_event->kmsg.msg.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    exec_event->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, exec_event->kmsg.path, exec_event->kmsg.msg.path_size)) {
            goto out_fail;
        }  else {
            copied += exec_event->kmsg.msg.path_size;
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

    // Copy executed file
    if (unlink_event->kmsg.path && unlink_event->kmsg.msg.path_offset &&
        unlink_event->kmsg.msg.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    unlink_event->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, unlink_event->kmsg.path, unlink_event->kmsg.msg.path_size)) {
            goto out_fail;
        }  else {
            copied += unlink_event->kmsg.msg.path_size;
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

    case DYNSEC_EVENT_TYPE_UNLINK:
        {
            const struct dynsec_unlink_event *unlink_event = 
                                    dynsec_event_to_unlink(dynsec_event);
            return copy_unlink_event(unlink_event, p, count);
        }
        break;

    default:
        break;
    }

    pr_info("%s: Invalid Event Type\n", __func__);
    return -EINVAL;
}

// Fill in event data and compute payload
bool fill_in_bprm_set_creds(struct dynsec_exec_event *exec_event,
                            const struct linux_binprm *bprm, gfp_t mode)
{
    bool found_ino = false;
    bool found_dev = false;
    char *buf = NULL;
    char *p = NULL;

    if (!exec_event || !bprm) {
        return false;
    }

    exec_event->kmsg.hdr.payload = 0;

    // hdr data
    exec_event->kmsg.hdr.req_id = exec_event->event.req_id;
    exec_event->kmsg.hdr.event_type = exec_event->event.event_type;

    exec_event->kmsg.hdr.payload += sizeof(exec_event->kmsg.hdr);

    // pid and tgid
    exec_event->kmsg.msg.pid = current->pid;
    exec_event->kmsg.msg.tgid = current->tgid;
    if (current->real_parent) {
        exec_event->kmsg.msg.ppid = current->real_parent->tgid;
    }

    // user DAC context
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    exec_event->kmsg.msg.uid = from_kuid(&init_user_ns, current_uid());
    exec_event->kmsg.msg.euid = from_kuid(&init_user_ns, current_euid());
    exec_event->kmsg.msg.gid = from_kgid(&init_user_ns, current_gid());
    exec_event->kmsg.msg.egid = from_kgid(&init_user_ns, current_egid());
#else
    exec_event->kmsg.msg.uid = current_uid();
    exec_event->kmsg.msg.euid = current_euid();
    exec_event->kmsg.msg.gid = current_gid();
    exec_event->kmsg.msg.egid = current_egid();
#endif
    exec_event->kmsg.hdr.payload += sizeof(exec_event->kmsg.msg);

    // file context
    // Should we provide file DAC ctx?
    if (bprm->file->f_path.dentry->d_inode) {
        exec_event->kmsg.msg.ino = bprm->file->f_path.dentry->d_inode->i_ino;
        found_ino = true;
    }
    if (bprm->file->f_path.mnt->mnt_sb) {
        exec_event->kmsg.msg.sb_magic = bprm->file->f_path.mnt->mnt_sb->s_magic;
        exec_event->kmsg.msg.dev = bprm->file->f_path.mnt->mnt_sb->s_dev;
        found_dev = true;
    } else if (bprm->file->f_path.dentry->d_sb) {
        exec_event->kmsg.msg.sb_magic = bprm->file->f_path.dentry->d_sb->s_magic;
        exec_event->kmsg.msg.dev = bprm->file->f_path.dentry->d_sb->s_dev;
        found_dev = true;
    }

#define EXEC_PATH_SZ 4096
    buf = kzalloc(EXEC_PATH_SZ, mode);
    if (!buf) {
        return true;
    }

    p = dynsec_d_path(&bprm->file->f_path, buf, EXEC_PATH_SZ);
    if (!IS_ERR(p) || (p && *p)) {
        if (likely(p > buf)) {
            memmove(buf, p, buf - p + EXEC_PATH_SZ -1);
        }
        if (likely(*buf)) {
            exec_event->kmsg.msg.path_size = buf - p + EXEC_PATH_SZ;
            exec_event->kmsg.msg.path_offset = exec_event->kmsg.hdr.payload;

            exec_event->kmsg.hdr.payload += exec_event->kmsg.msg.path_size;
            exec_event->kmsg.path = buf;
        } else {
            // memmove alignment off!
            kfree(buf);
            buf = NULL;
        }
    } else {
        kfree(buf);
        buf = NULL;
    }

    return true;
}

bool fill_in_inode_unlink(struct dynsec_unlink_event *unlink_event,
                          struct inode *dir, struct dentry *dentry, gfp_t mode)
{
    bool found_ino = false;
    bool found_dev = false;
    char *buf = NULL;
    char *p = NULL;

    if (!unlink_event || !dentry) {
        return false;
    }

    unlink_event->kmsg.hdr.payload = 0;

    // hdr data
    unlink_event->kmsg.hdr.req_id = unlink_event->event.req_id;
    unlink_event->kmsg.hdr.event_type = unlink_event->event.event_type;

    unlink_event->kmsg.hdr.payload += sizeof(unlink_event->kmsg.hdr);

    // pid and tgid
    unlink_event->kmsg.msg.pid = current->pid;
    unlink_event->kmsg.msg.tgid = current->tgid;
    if (current->real_parent) {
        unlink_event->kmsg.msg.ppid = current->real_parent->tgid;
    }

    // user DAC context
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    unlink_event->kmsg.msg.uid = from_kuid(&init_user_ns, current_uid());
    unlink_event->kmsg.msg.euid = from_kuid(&init_user_ns, current_euid());
    unlink_event->kmsg.msg.gid = from_kgid(&init_user_ns, current_gid());
    unlink_event->kmsg.msg.egid = from_kgid(&init_user_ns, current_egid());
#else
    unlink_event->kmsg.msg.uid = current_uid();
    unlink_event->kmsg.msg.euid = current_euid();
    unlink_event->kmsg.msg.gid = current_gid();
    unlink_event->kmsg.msg.egid = current_egid();
#endif
    unlink_event->kmsg.hdr.payload += sizeof(unlink_event->kmsg.msg);

    // dentry metadata
    if (dentry->d_inode) {
        unlink_event->kmsg.msg.ino = dentry->d_inode->i_ino;
        unlink_event->kmsg.msg.mode = dentry->d_inode->i_mode;
        found_ino = true;
    }
    if (dentry->d_sb) {
        unlink_event->kmsg.msg.sb_magic = dentry->d_sb->s_magic;
        unlink_event->kmsg.msg.dev = dentry->d_sb->s_dev;
        found_dev = true;
    }

    // Parent Info
    if (dir) {
        unlink_event->kmsg.msg.parent_ino = dir->i_ino;
        unlink_event->kmsg.msg.dev = dir->i_rdev;
    }
    if (dentry->d_parent != dentry) {
        if (dentry->d_parent->d_inode) {
            unlink_event->kmsg.msg.parent_ino = dentry->d_parent->d_inode->i_ino;
        }
        if (dentry->d_parent->d_sb) {
            unlink_event->kmsg.msg.dev = dentry->d_parent->d_sb->s_dev;
        }
    }

#define UNLINK_PATH_SZ 4096
    buf = kzalloc(UNLINK_PATH_SZ, mode);
    if (!buf) {
        return true;
    }

    p = dynsec_dentry_path(dentry, buf, UNLINK_PATH_SZ);
    if (!IS_ERR(p) || (p && *p)) {
        if (likely(p > buf)) {
            memmove(buf, p, buf - p + UNLINK_PATH_SZ -1);
        }
        if (likely(*buf)) {
            unlink_event->kmsg.msg.path_size = buf - p + UNLINK_PATH_SZ;
            unlink_event->kmsg.msg.path_offset = unlink_event->kmsg.hdr.payload;

            unlink_event->kmsg.hdr.payload += unlink_event->kmsg.msg.path_size;
            unlink_event->kmsg.path = buf;
        } else {
            // memmove alignment off!
            kfree(buf);
            buf = NULL;
        }
    } else {
        kfree(buf);
        buf = NULL;
    }

    return true;
}
