// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "process-tracking.h"
#include "cb-spinlock.h"
#include "cb-banning.h"
#include "path-buffers.h"
#include "event-factory.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define MMAP_ADDRESS() 0
int ec_lsm_mmap_file(struct file *file,
                  unsigned long reqprot, unsigned long prot,
                  unsigned long flags)
#else
#define MMAP_ADDRESS() addr
int ec_lsm_file_mmap(struct file *file,
                  unsigned long reqprot, unsigned long prot,
                  unsigned long flags, unsigned long addr,
                  unsigned long addr_only)
#endif
{
    int xcode;
    ProcessHandle *process_handle = NULL;
    PathData *path_data = NULL;
    pid_t pid = ec_getpid(current);

    DECLARE_ATOMIC_CONTEXT(context, pid);

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY((prot & PROT_EXEC) && !(prot & PROT_WRITE));

    TRY(file);

    // Skip if deleted
    TRY(!d_unlinked(file->f_path.dentry));

    TRY(!ec_banning_IgnoreProcess(&context, pid));

    // Skip if not interesting
    TRY(ec_is_interesting_file(file));

    // TODO: Add logic here to kill a process based on banned inode.
    //       There was logic here that made the check, but did not actually kill
    //       anything.

    //
    // This is a valid file, allocate an event
    //
    {
        struct path_lookup path_lookup = {
            .file = file,
            .ignore_spcial = true,
        };

        path_data = ec_file_get_path_data(&path_lookup, &context);
        TRY(path_data);
    }

    process_handle = ec_get_procinfo_and_create_process_start_if_needed(pid, "MODLOAD", &context);
    ec_event_send_modload(
        process_handle,
        CB_EVENT_TYPE_MODULE_LOAD,
        path_data,
        MMAP_ADDRESS(),
        &context);

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, &context);
    ec_path_cache_put(path_data, &context);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    xcode = 0;  // original_ops are none of our business
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    xcode = g_original_ops_ptr->mmap_file(file, reqprot, prot, flags);
#else
    xcode = g_original_ops_ptr->file_mmap(file, reqprot, prot, flags, addr, addr_only);
#endif

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}
