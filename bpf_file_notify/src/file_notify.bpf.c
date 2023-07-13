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

// SEC("?lsm.s/file_open")
// int BPF_PROG(lsm_file_open_s, struct file *file)
// {

// }


SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
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

            // Log to userspace here ...
        }
    }

    // Potentially do some reputation magic score here:
    //
    // Voodoo ...
    //

out:
    return ret;
}
