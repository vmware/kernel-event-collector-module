// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "hook-tracking.h"
#include "cb-spinlock.h"
#include "process-context.h"
#include "priv.h"

static struct hook_tracking_node
{
    uint64_t          lock;
    struct list_head  context_list;
    uint64_t          count;
} s_hook_tracking;

bool hook_tracking_initialize(ProcessContext *context)
{
    INIT_LIST_HEAD(&(s_hook_tracking.context_list));
    cb_spinlock_init(&s_hook_tracking.lock, context);
    s_hook_tracking.count = 0;
    return true;
}

void hook_tracking_shutdown(ProcessContext *context)
{
    cb_spinlock_destroy(&s_hook_tracking.lock, context);
}

void hook_tracking_add_entry(ProcessContext *context)
{
    CANCEL_VOID(context);

    // Ensure we are not adding a context twice
    // We don't expect this to ever happen, but we did see this case in the past
    //  We can aviod this by controlling how we call our own functions
    if (!list_empty(&(context->list)))
    {
        TRACE(DL_WARNING, "Detected recursion %s %d\n",
                      context->hook_name,
                      context->pid);
        return;
    }

    cb_write_lock(&s_hook_tracking.lock, context);
    list_add(&(context->list), &s_hook_tracking.context_list);
    ++s_hook_tracking.count;
    cb_write_unlock(&s_hook_tracking.lock, context);
}

void hook_tracking_del_entry(ProcessContext *context)
{
    CANCEL_VOID(context);

    // Ensure we are not removing a context which is not already in the list
    // We don't expect this to ever happen, but we did see this case in the past
    //  We can aviod this by controlling how we call our own functions
    CANCEL_VOID(!list_empty(&(context->list)));

    cb_write_lock(&s_hook_tracking.lock, context);
    list_del_init(&(context->list));
    --s_hook_tracking.count;
    cb_write_unlock(&s_hook_tracking.lock, context);
}

// This will be called in the module disable logic when we need to wait for hooks
//  to exit befor the module is disabled
int hook_tracking_print_active(ProcessContext *context)
{
    struct timespec current_time = get_current_timespec();
    ProcessContext *list_entry;

    cb_read_lock(&s_hook_tracking.lock, context);
    list_for_each_entry(list_entry, &s_hook_tracking.context_list, list)
    {
        pr_info("Active hook %s by %d for %ld seconds\n",
            list_entry->hook_name,
            list_entry->pid,
            current_time.tv_sec - list_entry->enter_time.tv_sec);
    }
    cb_read_unlock(&s_hook_tracking.lock, context);

    return 0;
}

// This is called when reading the proc file
int cb_show_active_hooks(struct seq_file *seq_file, void *v)
{
    struct timespec  current_time = get_current_timespec();

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));


    ProcessContext *list_entry;

    seq_printf(seq_file, "%20s | %6s | %6s\n",
                "Hook", "PID", "TIME");

    cb_read_lock(&s_hook_tracking.lock, &context);
    list_for_each_entry(list_entry, &s_hook_tracking.context_list, list)
    {
        seq_printf(seq_file, "%20s | %6d | %6ld |\n",
                      list_entry->hook_name,
                      list_entry->pid,
                      current_time.tv_sec - list_entry->enter_time.tv_sec);
    }

    seq_printf(seq_file, "Total Active %llu\n",
                    s_hook_tracking.count);
    cb_read_unlock(&s_hook_tracking.lock, &context);

    return 0;
}
