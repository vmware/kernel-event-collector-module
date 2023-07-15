/*
 * Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/errno.h>

#include "file_notify_transport.h"

#define FMODE_EXEC      ((fmode_t)0x20)


char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_INODE_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct inode_cache_entry);
} inode_storage_map SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
//     __type(key, int);
//     __type(value, struct task_cache_entry);
// } task_storage_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct file_notify_msg);
} xpad SEC(".maps");


static const struct file_notify_msg empty_dummy = {};

static __always_inline void *current_blob(void)
{
    u32 index = 0;

    (void)bpf_map_update_elem(&xpad, &index, &empty_dummy, BPF_ANY);

    return bpf_map_lookup_elem(&xpad, &index);
}

// Sleepable scratchpad
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 256);
//     __type(key, u32);
//     __type(value, struct file_notify_msg);
// } xpad_s SEC(".maps");

// SEC("?lsm.s/file_open")
// int BPF_PROG(lsm_file_open_s, struct file *file)
// {

// }


SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    bool notify = false;
    int ret = 0;
    struct inode_cache_entry *entry = NULL;

    if (!file->f_inode)
    {
        return 0;
    }

    // struct inode * or other kernel objects should not use CORE
    // or be careful when using CORE functions when using storage maps.
    // LSM and fentry/fexit hooks have special ways to auto-map the fields.
    entry = bpf_inode_storage_get(&inode_storage_map, file->f_inode, 0, 0);
    // Assumes we don't care about tracking files dynamically from BPF
    if (!entry)
    {
        goto out;
    }

    // Check if file is banned
    unsigned long f_flags = BPF_CORE_READ(file, f_flags);

    if (f_flags & FMODE_EXEC)
    {
        if (entry->type_flags & INODE_TYPE_LABEL_BANNED)
        {
            ret = -EPERM;
            __sync_add_and_fetch(&entry->total_deny, 1);

            notify = true;
        }
    }

    if (entry->type_flags & INODE_TYPE_LABEL_INTERESTING)
    {
        notify = true;
    }

    if (entry->type_flags & INODE_TYPE_LABEL_IGNORE)
    {
        notify = false;
    }

    // Potentially do some reputation magic score here:
    //
    // Voodoo ...
    //

out:

    if (notify)
    {
        struct task_struct *task = (typeof(task))bpf_get_current_task();
        struct file_notify_msg *msg = current_blob();

        if (msg)
        {
            u16 blob_size = 0;
            u32 payload = offsetof(typeof(*msg), blob);
            char *blob_pos = msg->blob;

            msg->hdr.ts = bpf_ktime_get_ns();

            if (entry) {
                msg->inode_entry = *entry;
            }

            // Fill in task info like exe, task cred data etc
            BPF_CORE_READ_INTO(&msg->task_ctx.tid, task, pid);
            BPF_CORE_READ_INTO(&msg->task_ctx.pid, task, tgid);
            BPF_CORE_READ_INTO(&msg->task_ctx.comm, task, comm);

            // Fill in file info as well like fs_magic, inode, device
            // uid, gid, parent directory info too.

            // If bpf_d_path doesn't work at this context for older
            // RHEL 8 kernels, create a legacy version of this LSM
            // hook and use the sensor.bpf.c blobify file path function.
            // However don't worry about truncation too much, that's
            // a silly, endless never ending problem.

            int ret = bpf_d_path(&file->f_path, &msg->blob, 4096);
            barrier_var(ret);
            if (ret <= 4096) {
                msg->path.type = BLOB_TYPE_DPATH;

                if (ret >= 0) {
                    blob_size = (u16)ret;
                }
                // When the path is too long send the whole buffer
                // to allow userspace to "find" the start of the
                // truncated path. Blob buffer area is all zeroed out,
                // so userspace can find it like our other kernel modules do.
                else if (ret == -ENAMETOOLONG) {
                    msg->path.flags |= BLOB_TYPE_FLAG__TRUNCATED;
                    blob_size = 4096;
                }
                else {
                    blob_size = 0;
                }
            }

            barrier_var(blob_size);
            if (blob_size <= 4096) {
                msg->path.type = BLOB_TYPE_DPATH;
                msg->path.size = blob_size;
                msg->path.offset = payload;

                payload += blob_size;
            }

            msg->hdr.payload = payload;
            barrier_var(payload);
            if (payload <= sizeof(*msg)) {
                bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                      msg, payload);
            }
        }
    }

    return ret;
}