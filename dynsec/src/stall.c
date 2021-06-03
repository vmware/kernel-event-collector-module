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
    exec_event->event.type = DYNSEC_LSM_bprm_set_creds;

    exec_event->kmsg.hdr.req_id = exec_event->event.req_id;
    exec_event->kmsg.hdr.type = exec_event->event.type;

    // pr_info("%s: req_id:%llu type:%#x\n", __func__,
    //         exec_event->event.req_id, exec_event->event.type);

    return &exec_event->event;
}

// Event allocation factory
struct dynsec_event *alloc_dynsec_event(uint32_t type, gfp_t mode)
{
    switch (type)
    {
    case DYNSEC_LSM_bprm_set_creds:
        return alloc_exec_event(mode);

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

    switch (dynsec_event->type)
    {
    case DYNSEC_LSM_bprm_set_creds:
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

    switch (dynsec_event->type)
    {
    case DYNSEC_LSM_bprm_set_creds:
        {
            struct dynsec_exec_event *exec_event =
                    dynsec_event_to_exec(dynsec_event);
            return exec_event->kmsg.hdr.payload;
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

// Copy to userspace
ssize_t copy_dynsec_event_to_user(const struct dynsec_event *dynsec_event,
                                  char *__user p, size_t count)
{
    if (!dynsec_event) {
        return -EINVAL;
    }

    // Copy might be different per event type
    switch (dynsec_event->type)
    {
    case DYNSEC_LSM_bprm_set_creds:
        {
            const struct dynsec_exec_event *dee = 
                                    dynsec_event_to_exec(dynsec_event);
            return copy_exec_event(dee, p, count);
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
    exec_event->kmsg.hdr.type = exec_event->event.type;

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
    }

    // file path - optional-ish
    // path here is just topical, we could just use dentry_path
#define EXEC_PATH_SZ 4096
    buf = kzalloc(EXEC_PATH_SZ, mode);
    if (!buf) {
        return true;
    }

    p = d_path(&bprm->file->f_path, buf, EXEC_PATH_SZ);
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
