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
#include <linux/file.h>
#include <linux/namei.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#endif
#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
// For <linux/backing-dev.h>
#include <linux/device.h>
#endif
#include <linux/backing-dev.h>

#include "dynsec.h"
#include "factory.h"
#include "path_utils.h"
#include "task_cache.h"
#include "task_utils.h"
#include "config.h"

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

#define init_event_data(EVENT_TYPE, EVENT, REPORT_FLAGS, HOOK) do { \
        init_dynsec_event(EVENT_TYPE, &EVENT->event);           \
        init_event_report_flags(EVENT, REPORT_FLAGS);           \
        EVENT->kmsg.hdr.hook_type = HOOK;                       \
        EVENT->kmsg.hdr.req_id = EVENT->event.req_id;           \
        EVENT->kmsg.hdr.event_type = EVENT->event.event_type;   \
        EVENT->kmsg.hdr.tid = EVENT->event.tid;                 \
        EVENT->kmsg.hdr.payload = sizeof(EVENT)->kmsg;          \
    } while (0)

#define prepare_hdr_data(subevent) do { \
        subevent->kmsg.hdr.report_flags = subevent->event.report_flags;   \
        subevent->kmsg.hdr.intent_req_id = subevent->event.intent_req_id; \
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

    // On default don't install a file to consumer of event queue
    file->kmsg.msg.fd = -1;

    return &file->event;
}

static struct dynsec_event *alloc_mmap_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_mmap_event *mmap = kzalloc(sizeof(*mmap), mode);

    if (!mmap) {
        return NULL;
    }

    init_event_data(event_type, mmap, report_flags, hook_type);

    return &mmap->event;
}

static struct dynsec_event *alloc_link_event(enum dynsec_event_type event_type,
                                             uint32_t hook_type, uint16_t report_flags,
                                             gfp_t mode)
{
    struct dynsec_link_event *link = kzalloc(sizeof(*link), mode);

    if (!link) {
        return NULL;
    }

    init_event_data(event_type, link, report_flags, hook_type);

    return &link->event;
}

static struct dynsec_event *alloc_symlink_event(enum dynsec_event_type event_type,
                                             uint32_t hook_type, uint16_t report_flags,
                                             gfp_t mode)
{
    struct dynsec_symlink_event *symlink = kzalloc(sizeof(*symlink), mode);

    if (!symlink) {
        return NULL;
    }

    init_event_data(event_type, symlink, report_flags, hook_type);

    return &symlink->event;
}

static struct dynsec_event *alloc_task_event(enum dynsec_event_type event_type,
                                             uint32_t hook_type, uint16_t report_flags,
                                             gfp_t mode)
{
    struct dynsec_task_event *task = kzalloc(sizeof(*task), mode);

    if (!task) {
        return NULL;
    }

    init_event_data(event_type, task, report_flags, hook_type);

    return &task->event;
}

static struct dynsec_event *alloc_ptrace_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_ptrace_event *ptrace = kzalloc(sizeof(*ptrace), mode);

    if (!ptrace) {
        return NULL;
    }

    init_event_data(event_type, ptrace, report_flags, hook_type);

    return &ptrace->event;
}

static struct dynsec_event *alloc_signal_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_signal_event *signal = kzalloc(sizeof(*signal), mode);

    if (!signal) {
        return NULL;
    }

    init_event_data(event_type, signal, report_flags, hook_type);

    return &signal->event;
}

static struct dynsec_event *alloc_task_dump_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type, uint16_t report_flags,
                                               gfp_t mode)
{
    struct dynsec_task_dump_event *task_dump = kzalloc(sizeof(*task_dump), mode);

    if (!task_dump) {
        return NULL;
    }

    init_event_data(event_type, task_dump, report_flags, hook_type);

    return &task_dump->event;
}


// Event allocation factory
struct dynsec_event *alloc_dynsec_event(enum dynsec_event_type event_type,
                                        uint32_t hook_type,
                                        uint16_t report_flags,
                                        gfp_t mode)
{
    // Disable stalling auto-magically
    if (!stall_mode_enabled()) {
        report_flags &= ~(DYNSEC_REPORT_STALL);
    }

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

    case DYNSEC_EVENT_TYPE_MMAP:
        return alloc_mmap_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_LINK:
        return alloc_link_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_SYMLINK:
        return alloc_symlink_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_CLONE:
    case DYNSEC_EVENT_TYPE_EXIT:
        return alloc_task_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_PTRACE:
        return alloc_ptrace_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_SIGNAL:
        return alloc_signal_event(event_type, hook_type, report_flags, mode);

    case DYNSEC_EVENT_TYPE_TASK_DUMP:
        return alloc_task_dump_event(event_type, hook_type, report_flags, mode);

    default:
        break;
    }
    return NULL;
}

// Set the last event for task_cache for PreActions
void prepare_non_report_event(enum dynsec_event_type event_type, gfp_t mode)
{
    struct event_track dummy_track  = {
        .track_flags = 0,
        .event_type = event_type,
        .report_flags = 0,
        .req_id = 0,
    };

    if (event_type < DYNSEC_EVENT_TYPE_TASK_DUMP) {
        (void)task_cache_set_last_event(current->pid, &dummy_track, NULL, mode);
    }
}

void prepare_dynsec_event(struct dynsec_event *dynsec_event, gfp_t mode)
{
    struct event_track event;
    struct event_track prev_event;

    if (!dynsec_event) {
        return;
    }

    // Disable stalling auto-magically
    if (!stall_mode_enabled()) {
        dynsec_event->report_flags &= ~(DYNSEC_REPORT_STALL);
    }

    event.track_flags = (TRACK_EVENT_REQ_ID_VALID | TRACK_EVENT_REPORTABLE);
    event.report_flags = dynsec_event->report_flags;
    event.req_id = dynsec_event->req_id;
    event.event_type = dynsec_event->event_type;
    memset(&prev_event, 0, sizeof(prev_event));

    // Find the last event. If it's an PreAction aka DYNSEC_REPORT_INTENT
    // and it was meant to be reportable then adjust req_id or tell us
    if (dynsec_event->event_type >= DYNSEC_EVENT_TYPE_HEALTH) {
        return;
    }

    if (event.report_flags & DYNSEC_REPORT_INTENT) {
        (void)task_cache_set_last_event(dynsec_event->tid, &event,
                                        NULL, mode);
    } else {
        int error = task_cache_set_last_event(dynsec_event->tid, &event,
                                              &prev_event, mode);
        // Copy over modified report flags due to cache opts
        if (!error) {
            dynsec_event->report_flags = event.report_flags;
        }

        if (!error && (prev_event.report_flags & DYNSEC_REPORT_INTENT) &&
                (prev_event.track_flags & TRACK_EVENT_REPORTABLE) &&
                prev_event.event_type == event.event_type) {
            dynsec_event->intent_req_id = prev_event.req_id;
            dynsec_event->report_flags |= DYNSEC_REPORT_INTENT_FOUND;
        }
    }

    // Set Queueing Priority When Not High Priority
    if (lazy_notifier_enabled()) {
        if (!(dynsec_event->report_flags & (DYNSEC_REPORT_STALL|DYNSEC_REPORT_HI_PRI))) {
            dynsec_event->report_flags |= DYNSEC_REPORT_LO_PRI;
        }
    }

    // A trace mode placed here to disable stalling at the
    // very last step before we enqueue things would be nice.

    switch (dynsec_event->event_type)
    {
    case DYNSEC_EVENT_TYPE_EXEC:
        prepare_hdr_data(dynsec_event_to_exec(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_UNLINK:
    case DYNSEC_EVENT_TYPE_RMDIR:
        prepare_hdr_data(dynsec_event_to_unlink(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_RENAME:
        prepare_hdr_data(dynsec_event_to_rename(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_SETATTR:
        prepare_hdr_data(dynsec_event_to_setattr(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_CREATE:
    case DYNSEC_EVENT_TYPE_MKDIR:
        prepare_hdr_data(dynsec_event_to_create(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_OPEN:
    case DYNSEC_EVENT_TYPE_CLOSE:
        prepare_hdr_data(dynsec_event_to_file(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_MMAP:
        prepare_hdr_data(dynsec_event_to_mmap(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_LINK:
        prepare_hdr_data(dynsec_event_to_link(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_SYMLINK:
        prepare_hdr_data(dynsec_event_to_symlink(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_CLONE:
    case DYNSEC_EVENT_TYPE_EXIT:
        prepare_hdr_data(dynsec_event_to_task(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_PTRACE:
        prepare_hdr_data(dynsec_event_to_ptrace(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_SIGNAL:
        prepare_hdr_data(dynsec_event_to_signal(dynsec_event));
        break;

    case DYNSEC_EVENT_TYPE_TASK_DUMP:
        prepare_hdr_data(dynsec_event_to_task_dump(dynsec_event));
        break;

    default:
        break;
    }
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

    case DYNSEC_EVENT_TYPE_MMAP:
        {
            struct dynsec_mmap_event *mmap =
                    dynsec_event_to_mmap(dynsec_event);

            kfree(mmap->path);
            mmap->path = NULL;
            kfree(mmap);
        }
        break;

    case DYNSEC_EVENT_TYPE_LINK:
        {
            struct dynsec_link_event *link =
                    dynsec_event_to_link(dynsec_event);

            kfree(link->old_path);
            link->old_path = NULL;
            kfree(link->new_path);
            link->new_path = NULL;
            kfree(link);
        }
        break;

    case DYNSEC_EVENT_TYPE_SYMLINK:
        {
            struct dynsec_symlink_event *symlink =
                    dynsec_event_to_symlink(dynsec_event);

            kfree(symlink->path);
            symlink->path = NULL;
            kfree(symlink->target_path);
            symlink->target_path = NULL;
            kfree(symlink);
        }
        break;

    case DYNSEC_EVENT_TYPE_CLONE:
    case DYNSEC_EVENT_TYPE_EXIT:
        {
            struct dynsec_task_event *task =
                    dynsec_event_to_task(dynsec_event);
            kfree(task->exec_path);
            task->exec_path = NULL;
            kfree(task);
        }
        break;

    case DYNSEC_EVENT_TYPE_PTRACE:
        {
            struct dynsec_ptrace_event *ptrace =
                    dynsec_event_to_ptrace(dynsec_event);

            kfree(ptrace);
        }
        break;

    case DYNSEC_EVENT_TYPE_SIGNAL:
        {
            struct dynsec_signal_event *signal =
                    dynsec_event_to_signal(dynsec_event);

            kfree(signal);
        }
        break;

    case DYNSEC_EVENT_TYPE_TASK_DUMP:
        {
            struct dynsec_task_dump_event *task_dump =
                    dynsec_event_to_task_dump(dynsec_event);
            kfree(task_dump->exec_path);
            task_dump->exec_path = NULL;
            kfree(task_dump);
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

    case DYNSEC_EVENT_TYPE_MMAP:
        {
            struct dynsec_mmap_event *mmap =
                    dynsec_event_to_mmap(dynsec_event);
            return mmap->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_LINK:
        {
            struct dynsec_link_event *link =
                    dynsec_event_to_link(dynsec_event);
            return link->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_SYMLINK:
        {
            struct dynsec_symlink_event *symlink =
                    dynsec_event_to_symlink(dynsec_event);
            return symlink->kmsg.hdr.payload;
        }
        break;


    case DYNSEC_EVENT_TYPE_CLONE:
    case DYNSEC_EVENT_TYPE_EXIT:
        {
            struct dynsec_task_event *task =
                    dynsec_event_to_task(dynsec_event);
            return task->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_PTRACE:
        {
            struct dynsec_ptrace_event *ptrace =
                    dynsec_event_to_ptrace(dynsec_event);
            return ptrace->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_SIGNAL:
        {
            struct dynsec_signal_event *signal =
                    dynsec_event_to_signal(dynsec_event);
            return signal->kmsg.hdr.payload;
        }
        break;

    case DYNSEC_EVENT_TYPE_TASK_DUMP:
        {
            struct dynsec_task_dump_event *task_dump =
                    dynsec_event_to_task_dump(dynsec_event);
            return task_dump->kmsg.hdr.payload;
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

static ssize_t copy_mmap_event(const struct dynsec_mmap_event *mmap,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < mmap->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &mmap->kmsg, sizeof(mmap->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(mmap->kmsg);
        p += sizeof(mmap->kmsg);
    }


    if (mmap->path && mmap->kmsg.msg.file.path_offset &&
        mmap->kmsg.msg.file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    mmap->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, mmap->path, mmap->kmsg.msg.file.path_size)) {
            goto out_fail;
        } else {
            copied += mmap->kmsg.msg.file.path_size;
            p += mmap->kmsg.msg.file.path_size;
        }
    }

    if (mmap->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                mmap->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

static ssize_t copy_link_event(const struct dynsec_link_event *link,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < link->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &link->kmsg, sizeof(link->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(link->kmsg);
        p += sizeof(link->kmsg);
    }

    // Copy Old Path
    if (link->old_path && link->kmsg.msg.old_file.path_offset &&
        link->kmsg.msg.old_file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    link->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, link->old_path, link->kmsg.msg.old_file.path_size)) {
            goto out_fail;
        }  else {
            copied += link->kmsg.msg.old_file.path_size;
            p += link->kmsg.msg.old_file.path_size;
        }
    }

    // Copy New Path
    if (link->new_path && link->kmsg.msg.new_file.path_offset &&
        link->kmsg.msg.new_file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    link->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, link->new_path, link->kmsg.msg.new_file.path_size)) {
            goto out_fail;
        }  else {
            copied += link->kmsg.msg.new_file.path_size;
            p += link->kmsg.msg.new_file.path_size;
        }
    }

    if (link->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                link->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

static ssize_t copy_symlink_event(const struct dynsec_symlink_event *symlink,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < symlink->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &symlink->kmsg, sizeof(symlink->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(symlink->kmsg);
        p += sizeof(symlink->kmsg);
    }

    // Copy Actual Symlink File Path
    if (symlink->path && symlink->kmsg.msg.file.path_offset &&
        symlink->kmsg.msg.file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    symlink->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, symlink->path, symlink->kmsg.msg.file.path_size)) {
            goto out_fail;
        }  else {
            copied += symlink->kmsg.msg.file.path_size;
            p += symlink->kmsg.msg.file.path_size;
        }
    }

    // Target Path
    if (symlink->target_path && symlink->kmsg.msg.target.offset &&
        symlink->kmsg.msg.target.size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    symlink->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, symlink->target_path, symlink->kmsg.msg.target.size)) {
            goto out_fail;
        }  else {
            copied += symlink->kmsg.msg.target.size;
            p += symlink->kmsg.msg.target.size;
        }
    }

    if (symlink->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                symlink->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

static ssize_t copy_task_event(const struct dynsec_task_event *task,
                               char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < task->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &task->kmsg, sizeof(task->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(task->kmsg);
        p += sizeof(task->kmsg);
    }

    if (task->exec_path && task->kmsg.msg.exec_file.path_offset &&
        task->kmsg.msg.exec_file.path_size) {
        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    task->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, task->exec_path,
                         task->kmsg.msg.exec_file.path_size)) {
            goto out_fail;
        } else {
            copied += task->kmsg.msg.exec_file.path_size;
            p += task->kmsg.msg.exec_file.path_size;
        }
    }

    if (task->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                task->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

static ssize_t copy_ptrace_event(const struct dynsec_ptrace_event *ptrace,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < ptrace->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &ptrace->kmsg, sizeof(ptrace->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(ptrace->kmsg);
        p += sizeof(ptrace->kmsg);
    }

    if (ptrace->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                ptrace->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

static ssize_t copy_signal_event(const struct dynsec_signal_event *signal,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < signal->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &signal->kmsg, sizeof(signal->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(signal->kmsg);
        p += sizeof(signal->kmsg);
    }

    if (signal->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                signal->kmsg.hdr.payload, copied);
        goto out_fail;
    }

    return copied;

out_fail:
    return -EFAULT;
}

static ssize_t copy_task_dump_event(const struct dynsec_task_dump_event *task_dump,
                                 char *__user buf, size_t count)
{
    int copied = 0;
    char *__user p = buf;

    if (count < task_dump->kmsg.hdr.payload) {
        return -EINVAL;
    }

    // Copy header
    if (copy_to_user(p, &task_dump->kmsg, sizeof(task_dump->kmsg))) {
        goto out_fail;
    } else {
        copied += sizeof(task_dump->kmsg);
        p += sizeof(task_dump->kmsg);
    }


    if (task_dump->exec_path && task_dump->kmsg.msg.exec_file.path_offset &&
        task_dump->kmsg.msg.exec_file.path_size) {

        if (buf + copied != p) {
            pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                    task_dump->kmsg.hdr.payload, copied);
            goto out_fail;
        }

        if (copy_to_user(p, task_dump->exec_path,
                         task_dump->kmsg.msg.exec_file.path_size)) {
            goto out_fail;
        } else {
            copied += task_dump->kmsg.msg.exec_file.path_size;
            p += task_dump->kmsg.msg.exec_file.path_size;
        }
    }

    if (task_dump->kmsg.hdr.payload != copied) {
        pr_info("%s:%d payload:%u != copied:%d\n", __func__, __LINE__,
                task_dump->kmsg.hdr.payload, copied);
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

    case DYNSEC_EVENT_TYPE_MMAP:
        {
            const struct dynsec_mmap_event *mmap =
                                    dynsec_event_to_mmap(dynsec_event);
            return copy_mmap_event(mmap, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_LINK:
        {
            const struct dynsec_link_event *link =
                                    dynsec_event_to_link(dynsec_event);
            return copy_link_event(link, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_SYMLINK:
        {
            const struct dynsec_symlink_event *symlink =
                                    dynsec_event_to_symlink(dynsec_event);
            return copy_symlink_event(symlink, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_CLONE:
    case DYNSEC_EVENT_TYPE_EXIT:
        {
            const struct dynsec_task_event *task =
                                    dynsec_event_to_task(dynsec_event);
            return copy_task_event(task, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_PTRACE:
        {
            const struct dynsec_ptrace_event *ptrace =
                                    dynsec_event_to_ptrace(dynsec_event);
            return copy_ptrace_event(ptrace, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_SIGNAL:
        {
            const struct dynsec_signal_event *signal =
                                    dynsec_event_to_signal(dynsec_event);
            return copy_signal_event(signal, p, count);
        }
        break;

    case DYNSEC_EVENT_TYPE_TASK_DUMP:
        {
            const struct dynsec_task_dump_event *task_dump =
                                    dynsec_event_to_task_dump(dynsec_event);
            return copy_task_dump_event(task_dump, p, count);
        }
        break;

    default:
        break;
    }

    pr_info("%s: Invalid Event Type\n", __func__);
    return -EINVAL;
}

// Default values for uid/gid should be -1
static void fill_in_cred(struct dynsec_cred *dynsec_cred, const struct cred *cred)
{
    if (dynsec_cred && cred) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        dynsec_cred->uid = from_kuid(&init_user_ns, cred->uid);
        dynsec_cred->euid = from_kuid(&init_user_ns, cred->euid);
        dynsec_cred->gid = from_kgid(&init_user_ns, cred->gid);
        dynsec_cred->egid = from_kgid(&init_user_ns, cred->egid);
        dynsec_cred->fsuid = from_kuid(&init_user_ns, cred->fsuid);
        dynsec_cred->fsgid = from_kgid(&init_user_ns, cred->fsgid);
#else
        dynsec_cred->uid = cred->uid;
        dynsec_cred->euid = cred->euid;
        dynsec_cred->gid = cred->gid;
        dynsec_cred->egid = cred->egid;
        dynsec_cred->fsuid = cred->fsuid;
        dynsec_cred->fsgid = cred->fsgid;
#endif
        dynsec_cred->securebits = cred->securebits;
    }
}

static void __fill_in_task_ctx(const struct task_struct *task,
                               bool check_parent,
                               struct dynsec_task_ctx *task_ctx)
{
    task_ctx->mnt_ns = get_mnt_ns_id(task);
    if (task_ctx->mnt_ns) {
        task_ctx->extra_ctx |= DYNSEC_TASK_HAS_MNT_NS;
    }
    task_ctx->tid = task->pid;
    task_ctx->pid = task->tgid;
    if (check_parent && task->parent) {
        task_ctx->ppid = task->parent->tgid;
    }
    if (check_parent && task->real_parent) {
        task_ctx->real_parent_id = task->real_parent->tgid;
    }

    // user DAC context
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    task_ctx->uid = from_kuid(&init_user_ns, task_cred_xxx(task, uid));
    task_ctx->euid = from_kuid(&init_user_ns, task_cred_xxx(task, euid));
    task_ctx->gid = from_kgid(&init_user_ns, task_cred_xxx(task, gid));
    task_ctx->egid = from_kgid(&init_user_ns, task_cred_xxx(task, egid));
#else
    task_ctx->uid = task_cred_xxx(task, uid);
    task_ctx->euid = task_cred_xxx(task, euid);
    task_ctx->gid = task_cred_xxx(task, gid);
    task_ctx->egid = task_cred_xxx(task, egid);
#endif

    task_ctx->flags = task->flags;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    task_ctx->start_time = task->start_time;
#else
    task_ctx->start_time = (task->start_time.tv_sec * 10000000) +
        task->start_time.tv_nsec;
#endif

    if (task->in_execve) {
        task_ctx->extra_ctx |= DYNSEC_TASK_IN_EXECVE;
    }
    if (task->mm) {
        task_ctx->extra_ctx |= DYNSEC_TASK_HAS_MM;
    }
    BUILD_BUG_ON(DYNSEC_TASK_COMM_LEN != TASK_COMM_LEN);
    memcpy(task_ctx->comm, task->comm, DYNSEC_TASK_COMM_LEN);

// #if defined(RHEL_MAJOR) && RHEL_MAJOR == 8
//    task_ctx->self_exec_id = task->task_struct_rh->self_exec_id;
//    task_ctx->parent_exec_id = task->task_struct_rh->parent_exec_id;
// #else
//    task_ctx->self_exec_id = task->self_exec_id;
//    task_ctx->parent_exec_id = task->parent_exec_id;
// #endif
}

static void fill_in_task_ctx(struct dynsec_task_ctx *task_ctx)
{
    if (task_ctx) {
        __fill_in_task_ctx(current, true, task_ctx);
    }
}

static inline bool has_backing_device_info(const struct super_block *sb)
{
    const struct backing_dev_info *bdi;

    if (!sb) {
        return false;
    }
    bdi = (const struct backing_dev_info *)sb->s_bdi;
    if (!bdi) {
        return false;
    }

    if (bdi == &noop_backing_dev_info) {
        return false;
    }
// TODO: Determine absolute kver this really goes away
#ifdef BDI_CAP_SWAP_BACKED
    if (bdi == &default_backing_dev_info) {
        return false;
    }
    if (bdi->capabilities & BDI_CAP_SWAP_BACKED) {
        return false;
    }
    return true;
#else
    // Checking for an owning device always valid?
    if (!bdi->owner) {
        return false;
    }
    return true;
    // Typically the owner's devt will match the sb's s_dev,
    // when it has a backing device.
    // return (bdi->owner->devt == sb->s_dev);
#endif /* less than 4.18.0 */
}

static void fill_in_sb_data(struct dynsec_file *dynsec_file,
                            const struct super_block *sb)
{
    if (sb) {
        if (!(dynsec_file->attr_mask & DYNSEC_FILE_ATTR_DEVICE)) {
            dynsec_file->attr_mask |= DYNSEC_FILE_ATTR_DEVICE;
            dynsec_file->dev = new_encode_dev(sb->s_dev);
            dynsec_file->sb_magic = sb->s_magic;
        }

        if (!(dynsec_file->attr_mask & (DYNSEC_FILE_ATTR_HAS_BACKING)) &&
            has_backing_device_info(sb)) {
            dynsec_file->attr_mask |= DYNSEC_FILE_ATTR_HAS_BACKING;
        }
    }
}

static void fill_in_parent_sb_data(struct dynsec_file *dynsec_file,
                                   const struct super_block *sb)
{
    if (dynsec_file && sb) {
        if (!(dynsec_file->attr_mask & DYNSEC_FILE_ATTR_PARENT_DEVICE)) {
            dynsec_file->attr_mask |= DYNSEC_FILE_ATTR_PARENT_DEVICE;
            dynsec_file->parent_dev = new_encode_dev(sb->s_dev);
            // Currently does not send parent sb_magic value
        }

        if (!(dynsec_file->attr_mask & (DYNSEC_FILE_ATTR_PARENT_HAS_BACKING)) &&
            has_backing_device_info(sb)) {
            dynsec_file->attr_mask |= DYNSEC_FILE_ATTR_PARENT_HAS_BACKING;
        }
    }
}

static void fill_in_inode_data(struct dynsec_file *dynsec_file,
                                 const struct inode *inode)
{
    if (dynsec_file && inode) {
        dynsec_file->attr_mask |= DYNSEC_FILE_ATTR_INODE;
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
        dynsec_file->count = atomic_read(&inode->i_count);
        dynsec_file->nlink = inode->i_nlink;
        // This is likely in accurate and should be over written
        // by either dentry or vfsmount accessed super_block
        fill_in_sb_data(dynsec_file, inode->i_sb);
    }
}

// dentry based callers may want to call dget_parent if sleepable
static void fill_in_parent_data(struct dynsec_file *dynsec_file,
                                struct inode *parent_dir)
{
    if (dynsec_file && parent_dir) {
        dynsec_file->attr_mask |= DYNSEC_FILE_ATTR_PARENT_INODE;
        dynsec_file->parent_ino = parent_dir->i_ino;
        dynsec_file->parent_umode = parent_dir->i_mode;
        if (!IS_POSIXACL(parent_dir)) {
            dynsec_file->attr_mask |= DYNSEC_FILE_ATTR_POSIX_ACL;
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        dynsec_file->parent_uid = from_kuid(&init_user_ns, parent_dir->i_uid);
        dynsec_file->parent_gid = from_kgid(&init_user_ns, parent_dir->i_gid);
#else
        dynsec_file->parent_uid = parent_dir->i_uid;
        dynsec_file->parent_gid = parent_dir->i_gid;
#endif
    }
}

static void fill_in_preaction_data(struct dynsec_file *dynsec_file,
                                   const struct path *parent_path)
{
    if (dynsec_file && parent_path) {
        if (parent_path->dentry) {
            fill_in_parent_data(dynsec_file, parent_path->dentry->d_inode);
        }
        if (parent_path->mnt) {
            fill_in_parent_sb_data(dynsec_file, parent_path->mnt->mnt_sb);

            // Safe to assume parent device data will is the target's device
            // for preactions.
            if (!(dynsec_file->attr_mask & DYNSEC_FILE_ATTR_DEVICE)) {
                fill_in_sb_data(dynsec_file, parent_path->mnt->mnt_sb);
            }
        }
    }
}

static void fill_in_dentry_data(struct dynsec_file *dynsec_file,
                                  const struct dentry *dentry)
{
    if (dynsec_file && dentry) {
        fill_in_inode_data(dynsec_file, dentry->d_inode);
        fill_in_sb_data(dynsec_file, dentry->d_sb);

        // d_parent data is a best effort attempt.
        if (dentry->d_parent && !IS_ROOT(dentry)) {
            fill_in_parent_data(dynsec_file, dentry->d_parent->d_inode);
            fill_in_parent_sb_data(dynsec_file, dentry->d_parent->d_sb);
        }
        // Hint to userspace dentry has been deleted
        if (d_unlinked((struct dentry *)dentry)) {
            dynsec_file->attr_mask |= DYNSEC_FILE_ATTR_DELETED;
        }
    }
}

static void fill_in_file_data(struct dynsec_file *dynsec_file,
                              const struct path *path)
{
    if (!dynsec_file || !path) {
        return;
    }

    fill_in_dentry_data(dynsec_file, path->dentry);
    if (path->mnt) {
        fill_in_sb_data(dynsec_file, path->mnt->mnt_sb);
    }

#ifdef FILL_IN_REAL_PARENT
    // Attempt to get the actual parent not the d_parent.
    if (path->dentry && path->mnt) {
        if (path->dentry != path->mnt->mnt_root) {
            if (path->dentry->d_parent) {
                fill_in_parent_data(dynsec_file,
                                    path->dentry->d_parent->d_inode);
                fill_in_parent_sb_data(dynsec_file, path->mnt->mnt_sb);
            }
        } else {
            // TODO: Nice-to-have
            // If we can sleep we could provide a
            // deep copy path and call follow_down_one to get
            // the next mnt and dentry.
        }
    }
#endif /* FILL_IN_REAL_PARENT */
}

// Fill in event data and compute payload
bool fill_in_bprm_set_creds(struct dynsec_event *dynsec_event,
                            const struct linux_binprm *bprm, gfp_t mode)
{
    struct dynsec_exec_event *exec = NULL;
    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_EXEC) {
        return false;
    }

    exec = dynsec_event_to_exec(dynsec_event);
    fill_in_task_ctx(&exec->kmsg.msg.task);
    fill_in_cred(&exec->kmsg.msg.new_cred, bprm->cred);
    fill_in_file_data(&exec->kmsg.msg.file, &bprm->file->f_path);

    exec->path = dynsec_build_path(&bprm->file->f_path,
                                &exec->kmsg.msg.file,
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

    if (!dynsec_event ||
        !(dynsec_event->event_type == DYNSEC_EVENT_TYPE_UNLINK ||
          dynsec_event->event_type == DYNSEC_EVENT_TYPE_RMDIR)) {
        return false;
    }
    unlink = dynsec_event_to_unlink(dynsec_event);

    fill_in_task_ctx(&unlink->kmsg.msg.task);

    fill_in_dentry_data(&unlink->kmsg.msg.file, dentry);
    fill_in_parent_data(&unlink->kmsg.msg.file, dir);

    unlink->path = dynsec_build_dentry(dentry,
                                &unlink->kmsg.msg.file,
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

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_RENAME) {
        return false;
    }
    rename = dynsec_event_to_rename(dynsec_event);

    fill_in_task_ctx(&rename->kmsg.msg.task);

    fill_in_dentry_data(&rename->kmsg.msg.old_file, old_dentry);
    fill_in_parent_data(&rename->kmsg.msg.old_file, old_dir);

    fill_in_dentry_data(&rename->kmsg.msg.new_file, new_dentry);
    fill_in_parent_data(&rename->kmsg.msg.new_file, new_dir);

    rename->old_path = dynsec_build_dentry(old_dentry,
                                &rename->kmsg.msg.old_file,
                                mode);
    if (rename->old_path && rename->kmsg.msg.old_file.path_size) {
        rename->kmsg.msg.old_file.path_offset = rename->kmsg.hdr.payload;
        rename->kmsg.hdr.payload += rename->kmsg.msg.old_file.path_size;
    }

    rename->new_path = dynsec_build_dentry(new_dentry,
                                &rename->kmsg.msg.new_file,
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

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_SETATTR) {
        return false;
    }
    setattr = dynsec_event_to_setattr(dynsec_event);

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
                                    &setattr->kmsg.msg.file,
                                    mode);
    } else {
        fill_in_dentry_data(&setattr->kmsg.msg.file, dentry);
        setattr->path = dynsec_build_dentry(dentry,
                                    &setattr->kmsg.msg.file,
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

    if (!dynsec_event ||
        !(dynsec_event->event_type == DYNSEC_EVENT_TYPE_CREATE ||
          dynsec_event->event_type == DYNSEC_EVENT_TYPE_MKDIR)) {
        return false;
    }

    create = dynsec_event_to_create(dynsec_event);

    fill_in_task_ctx(&create->kmsg.msg.task);

    fill_in_dentry_data(&create->kmsg.msg.file, dentry);
    fill_in_parent_data(&create->kmsg.msg.file, dir);

    if (!dir || !IS_POSIXACL(dir)) {
        create->kmsg.msg.file.umode = (uint16_t)(umode & ~current_umask());
    }
    if (dynsec_event->event_type == DYNSEC_EVENT_TYPE_MKDIR) {
        create->kmsg.msg.file.umode |= S_IFDIR;
    } else {
        create->kmsg.msg.file.umode |= S_IFREG;
    }

    create->path = dynsec_build_dentry(dentry,
                                &create->kmsg.msg.file,
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

bool fill_in_inode_link(struct dynsec_event *dynsec_event,
                        struct dentry *old_dentry,
                        struct inode *dir, struct dentry *new_dentry,
                        gfp_t mode)
{
    struct dynsec_link_event *link = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_LINK) {
        return false;
    }

    link = dynsec_event_to_link(dynsec_event);

    fill_in_task_ctx(&link->kmsg.msg.task);

    // Should be complete info
    fill_in_dentry_data(&link->kmsg.msg.old_file, old_dentry);

    // For new_file we may want to copy over old_dentry metadata
    fill_in_dentry_data(&link->kmsg.msg.new_file, new_dentry);
    fill_in_parent_data(&link->kmsg.msg.new_file, dir);

    link->old_path = dynsec_build_dentry(old_dentry,
                                &link->kmsg.msg.old_file,
                                mode);
    if (link->old_path && link->kmsg.msg.old_file.path_size) {
        link->kmsg.msg.old_file.path_offset = link->kmsg.hdr.payload;
        link->kmsg.hdr.payload += link->kmsg.msg.old_file.path_size;
    }

    link->new_path = dynsec_build_dentry(new_dentry,
                                &link->kmsg.msg.new_file,
                                mode);
    if (link->new_path && link->kmsg.msg.new_file.path_size) {
        link->kmsg.msg.new_file.path_offset = link->kmsg.hdr.payload;
        link->kmsg.hdr.payload += link->kmsg.msg.new_file.path_size;
    }

    return true;
}

bool fill_in_inode_symlink(struct dynsec_event *dynsec_event,
                           struct inode *dir, struct dentry *dentry,
                           const char *old_name, gfp_t mode)
{
    struct dynsec_symlink_event *symlink = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_SYMLINK) {
        return false;
    }

    symlink = dynsec_event_to_symlink(dynsec_event);

    fill_in_task_ctx(&symlink->kmsg.msg.task);

    fill_in_dentry_data(&symlink->kmsg.msg.file, dentry);
    fill_in_parent_data(&symlink->kmsg.msg.file, dir);

    symlink->kmsg.msg.file.umode |= S_IFLNK;

    symlink->path = dynsec_build_dentry(dentry, &symlink->kmsg.msg.file, mode);

    if (symlink->path && symlink->kmsg.msg.file.path_size) {
        symlink->kmsg.msg.file.path_offset = symlink->kmsg.hdr.payload;
        symlink->kmsg.hdr.payload += symlink->kmsg.msg.file.path_size;
    }
    if (old_name && *old_name) {
        size_t size = strlen(old_name) + 1;

        symlink->target_path = kmalloc(size, mode);
        if (symlink->target_path) {
            memcpy(symlink->target_path, old_name, size);
            symlink->target_path[size - 1] = 0;
            symlink->kmsg.msg.target.size = (uint16_t)size;
            symlink->kmsg.msg.target.offset = symlink->kmsg.hdr.payload;
            symlink->kmsg.hdr.payload += symlink->kmsg.msg.target.size;
        }
    }

    return true;
}

bool fill_in_file_open(struct dynsec_event *dynsec_event, struct file *file,
                       gfp_t mode)
{
    struct dynsec_file_event *open = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_OPEN) {
        return false;
    }

    open = dynsec_event_to_file(dynsec_event);

    fill_in_task_ctx(&open->kmsg.msg.task);
    open->kmsg.msg.f_mode = file->f_mode;
    open->kmsg.msg.f_flags = file->f_flags;
    fill_in_file_data(&open->kmsg.msg.file, &file->f_path);

    open->path = dynsec_build_path(&file->f_path, &open->kmsg.msg.file, mode);

    if (open->path && open->kmsg.msg.file.path_size) {
        open->kmsg.msg.file.path_offset = open->kmsg.hdr.payload;
        open->kmsg.hdr.payload += open->kmsg.msg.file.path_size;
    }

    return true;
}

bool fill_in_file_free(struct dynsec_event *dynsec_event, struct file *file,
                       gfp_t mode)
{
    struct dynsec_file_event *close = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_CLOSE) {
        return false;
    }

    close = dynsec_event_to_file(dynsec_event);

    fill_in_task_ctx(&close->kmsg.msg.task);
    close->kmsg.msg.f_mode = file->f_mode;
    close->kmsg.msg.f_flags = file->f_flags;
    fill_in_file_data(&close->kmsg.msg.file, &file->f_path);

    // May want to provide dentry path
    close->path = dynsec_build_path(&file->f_path, &close->kmsg.msg.file, mode);

    if (close->path && close->kmsg.msg.file.path_size) {
        close->kmsg.msg.file.path_offset = close->kmsg.hdr.payload;
        close->kmsg.hdr.payload += close->kmsg.msg.file.path_size;
    }

    return true;
}

bool fill_in_file_mmap(struct dynsec_event *dynsec_event, struct file *file,
                       unsigned long prot, unsigned long flags, gfp_t mode)
{
    struct dynsec_mmap_event *mmap = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_MMAP) {
        return false;
    }

    mmap = dynsec_event_to_mmap(dynsec_event);

    fill_in_task_ctx(&mmap->kmsg.msg.task);

    mmap->kmsg.msg.mmap_prot = prot;
    mmap->kmsg.msg.mmap_flags = flags;

    if (file) {
        mmap->kmsg.msg.f_mode = file->f_mode;
        mmap->kmsg.msg.f_flags = file->f_flags;
        fill_in_file_data(&mmap->kmsg.msg.file, &file->f_path);

        // Older kernels have had issue with chrooted paths on mmap
        if (current->nsproxy && file->f_path.mnt) {
            mmap->path = dynsec_build_path(&file->f_path, &mmap->kmsg.msg.file, mode);
        } else {
            mmap->path = dynsec_build_dentry(file->f_path.dentry,
                                             &mmap->kmsg.msg.file, mode);
        }

        if (mmap->path && mmap->kmsg.msg.file.path_size) {
            mmap->kmsg.msg.file.path_offset = mmap->kmsg.hdr.payload;
            mmap->kmsg.hdr.payload += mmap->kmsg.msg.file.path_size;
        }
    }

    return true;
}

bool fill_task_free(struct dynsec_event *dynsec_event,
                    const struct task_struct *task)
{
    struct dynsec_task_event *exit = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_EXIT) {
        return false;
    }
    exit = dynsec_event_to_task(dynsec_event);

    __fill_in_task_ctx(task, true, &exit->kmsg.msg.task);

    return true;
}

static char *fill_in_task_exe(struct task_struct *task,
                              struct dynsec_file *dynsec_file, gfp_t mode);

bool fill_in_clone(struct dynsec_event *dynsec_event,
                   const struct task_struct *parent,
                   const struct task_struct *child,
                   uint16_t extra_ctx)
{
    struct dynsec_task_event *clone = NULL;

    if (!dynsec_event || !child ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_CLONE) {
        return false;
    }
    clone = dynsec_event_to_task(dynsec_event);

    clone->kmsg.msg.task.extra_ctx |= extra_ctx;
    if (parent) {
        __fill_in_task_ctx(child, false, &clone->kmsg.msg.task);
        clone->kmsg.msg.task.ppid = parent->tgid;
    } else {
        __fill_in_task_ctx(child, true, &clone->kmsg.msg.task);
    }

    get_task_struct((struct task_struct *)child);
    clone->exec_path = fill_in_task_exe((struct task_struct *)child,
                                        &clone->kmsg.msg.exec_file,
                                        GFP_ATOMIC);
    // Potentially defer put_task_struct to a kthread
    // in case we end freeing the task in a kprobe or tracepoint.
    put_task_struct((struct task_struct *)child);

    if (clone->exec_path && clone->kmsg.msg.exec_file.path_size) {
        clone->kmsg.msg.exec_file.path_offset = clone->kmsg.hdr.payload;
        clone->kmsg.hdr.payload += clone->kmsg.msg.exec_file.path_size;
    }

    return true;
}

bool fill_in_ptrace(struct dynsec_event *dynsec_event,
                    const struct task_struct *source,
                    const struct task_struct *target)
{
    struct dynsec_ptrace_event *ptrace = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_PTRACE) {
        return false;
    }
    ptrace = dynsec_event_to_ptrace(dynsec_event);

    __fill_in_task_ctx(source, true, &ptrace->kmsg.msg.source);
    __fill_in_task_ctx(target, true, &ptrace->kmsg.msg.target);

    return true;
}

bool fill_in_task_kill(struct dynsec_event *dynsec_event,
                       const struct task_struct *target, int sig)
{
    struct dynsec_signal_event *signal = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_SIGNAL) {
        return false;
    }
    signal = dynsec_event_to_signal(dynsec_event);

    // current task may not always be source of signal
    __fill_in_task_ctx(current, true, &signal->kmsg.msg.source);
    signal->kmsg.msg.signal = sig;
    __fill_in_task_ctx(target, true, &signal->kmsg.msg.target);

    return true;
}

//#ifndef CONFIG_SECURITY_PATH
static char *build_preaction_path(int dfd, const char __user *filename,
                                  int lookup_flags, struct dynsec_file *file)
{
    char *filebuf = NULL;
    char *input_buf = NULL;
    char *last_component = NULL;
    char *p = NULL;
    char *last = NULL;
    char *norm_path = NULL;
    int total_len = 0;
    int input_len = 0;
    int last_len = 0;
    int error = -EINVAL;
    long max_input_len;
    struct path parent_path;

    lookup_flags |= LOOKUP_FOLLOW;

    if (!filename || !file) {
        return ERR_PTR(-EINVAL);
    }
    if (dfd < 0 && dfd != AT_FDCWD) {
        return ERR_PTR(-EINVAL);
    }

    // A couple extra bytes to detect invalid component
    last_component = kzalloc(NAME_MAX + 2, GFP_KERNEL);
    if (!last_component) {
        return ERR_PTR(-ENOMEM);
    }
    // Setup raw last component
    last = last_component + NAME_MAX;
    *last = '\0';

    filebuf = kzalloc(PATH_MAX, GFP_KERNEL);
    if (!filebuf) {
        error = -ENOMEM;
        goto out_err_free;
    }
    filebuf[0] = 0;
    input_buf = filebuf;


    if (dfd >= 0) {
        char *bufp;
        struct file *dfd_file = fget(dfd);

        if (IS_ERR_OR_NULL(dfd_file)) {
            goto out_err_free;
        }
        if (!dfd_file->f_path.dentry || !dfd_file->f_path.mnt) {
            fput(dfd_file);
            goto out_err_free;
        }

        // // Might as well check if dir
        // if (!dfd_file->f_path.dentry || !d_is_dir(dfd_file->f_path.dentry)) {
        //     error = -ENOTDIR;
        //     fput(dfd_file);
        //     goto out_err_free;
        // }
        if (!dfd_file->f_path.dentry ||
            !dfd_file->f_path.dentry->d_inode ||
            !S_ISDIR(dfd_file->f_path.dentry->d_inode->i_mode)) {
            error = -ENOTDIR;
            fput(dfd_file);
            goto out_err_free;
        }

        bufp = dynsec_d_path(&dfd_file->f_path, filebuf, PATH_MAX);
        fput(dfd_file);
        dfd_file = NULL;

        if (IS_ERR_OR_NULL(bufp) || !*bufp) {
            error = -ENAMETOOLONG;
            goto out_err_free;
        }
        total_len = strlen(bufp);
        if (total_len >= PATH_MAX) {
            error = -ENAMETOOLONG;
            goto out_err_free;
        }
        memmove(filebuf, bufp, total_len);

        // Setup for appending user string
        filebuf[total_len] = '/';
        total_len += 1;
        input_buf = filebuf + total_len;
    }

    // TODO: Allocate own buffer for user filepath
    max_input_len = PATH_MAX - total_len;
    input_buf[max_input_len - 1] = 0; // aka filebuf[PATH_MAX - 1] = 0
    input_len = strncpy_from_user(input_buf, filename, max_input_len);
    if (input_len < 0) {
        error = input_len;
        goto out_err_free;
    }
    if (input_len == 0) {
        goto out_err_free;
    }
    if (input_len == max_input_len &&
        input_buf[max_input_len - 1] != 0) {
        error = -ENAMETOOLONG;
        goto out_err_free;
    }
    total_len += input_len;

    // pr_info("%s:%d dfd:%d input_len:%d '%s'", __func__, __LINE__,
    //         dfd, input_len, filebuf);


    // Chomp trailing slashes
    p = input_buf + input_len;
    while (p >= input_buf && *p == '/') {
        *p = '\0';
        p--;
        total_len--;
    }

    // copy component until we hit a barrier
    while (p >= input_buf && last > last_component) {
        if (*p == '/') {
            break;
        }
        last--;
        *last = *p;
        last_len++;

        *p = '\0';
        p--;
        total_len--;
    }
    if (last_len > NAME_MAX) {
        error = -ENAMETOOLONG;
        goto out_err_free;
    }
    if (!last_len) {
        error = -EINVAL;
        goto out_err_free;
    }

    // Normalize the filepath
    error = kern_path(filebuf, lookup_flags, &parent_path);
    if (error) {
        goto out_err_free;
    }

    error = -ENAMETOOLONG;

    fill_in_preaction_data(file, &parent_path);
    norm_path = dynsec_build_path(&parent_path, file, GFP_KERNEL);
    path_put(&parent_path);

    // Append the last component to the normalized or raw input data
    if (IS_ERR_OR_NULL(norm_path)) {
        int raw_len = strlen(filebuf);

        if (raw_len + 1 + last_len > PATH_MAX) {
            error = -ENAMETOOLONG;
            goto out_err_free;
        }
        filebuf[raw_len] = '/';
        raw_len += 1;
        strlcpy(filebuf + raw_len, last, last_len);
        file->path_size = (uint16_t)strlen(filebuf) + 1;
        file->attr_mask |= DYNSEC_FILE_ATTR_PATH_RAW;
        kfree(last_component);
        return filebuf;
    } else {
        int parent_len = strlen(norm_path);

        // parent + '/' + last component
        if (parent_len + 1 + last_len > PATH_MAX) {
            error = -ENAMETOOLONG;
            kfree(norm_path);
            goto out_err_free;
        }

        norm_path[parent_len] = '/';
        parent_len += 1;

        strlcpy(norm_path + parent_len, last, last_len);
        file->path_size = (uint16_t)strlen(norm_path) + 1;
        file->attr_mask |= DYNSEC_FILE_ATTR_PATH_FULL;
        kfree(filebuf);
        kfree(last_component);
        return norm_path;
    }

out_err_free:
    kfree(filebuf);
    kfree(last_component);
    return ERR_PTR(error);
}


bool fill_in_preaction_create(struct dynsec_event *dynsec_event,
                              int dfd, const char __user *filename,
                              int flags, umode_t umode)
{
    struct dynsec_create_event *create = NULL;

    if (!dynsec_event ||
        !(dynsec_event->report_flags & DYNSEC_REPORT_INTENT) ||
        !(dynsec_event->event_type == DYNSEC_EVENT_TYPE_CREATE ||
          dynsec_event->event_type == DYNSEC_EVENT_TYPE_MKDIR)) {
        return false;
    }
    create = dynsec_event_to_create(dynsec_event);

    fill_in_task_ctx(&create->kmsg.msg.task);

    create->path = build_preaction_path(dfd, filename, 0,
                                        &create->kmsg.msg.file);
    if (IS_ERR(create->path)) {
        create->path = NULL;
        return false;
    }

    create->kmsg.msg.file.umode = (uint16_t)(umode & ~current_umask());
    if (dynsec_event->event_type == DYNSEC_EVENT_TYPE_MKDIR) {
        create->kmsg.msg.file.umode |= S_IFDIR;
    } else if (dynsec_event->event_type == DYNSEC_EVENT_TYPE_CREATE) {
        create->kmsg.msg.file.umode |= S_IFREG;
    }

    if (create->path && create->kmsg.msg.file.path_size) {
        create->kmsg.msg.file.path_offset = create->kmsg.hdr.payload;
        create->kmsg.hdr.payload += create->kmsg.msg.file.path_size;
    }
    return true;
}

bool fill_in_preaction_rename(struct dynsec_event *dynsec_event,
                              int newdfd, const char __user *newname,
                              struct path *oldpath)
{
    int ret;
    struct path newpath;
    struct dynsec_rename_event *rename = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_RENAME) {
        return false;
    }
    rename = dynsec_event_to_rename(dynsec_event);

    fill_in_task_ctx(&rename->kmsg.msg.task);

    fill_in_file_data(&rename->kmsg.msg.old_file, oldpath);

    rename->old_path = dynsec_build_path(oldpath,
                                         &rename->kmsg.msg.old_file,
                                         GFP_KERNEL);
    if (rename->old_path && rename->kmsg.msg.old_file.path_size) {
        rename->kmsg.msg.old_file.path_offset = rename->kmsg.hdr.payload;
        rename->kmsg.hdr.payload += rename->kmsg.msg.old_file.path_size;
    }

    // New path could already exist
    ret = user_path_at(newdfd, newname, 0, &newpath);
    if (!ret) {
        fill_in_file_data(&rename->kmsg.msg.new_file, &newpath);
        rename->new_path = dynsec_build_path(&newpath,
                                             &rename->kmsg.msg.new_file,
                                             GFP_KERNEL);
        path_put(&newpath);
    } else {
        rename->new_path = build_preaction_path(newdfd, newname, 0,
                                                &rename->kmsg.msg.new_file);
        // Allow this bad intent to
        if (IS_ERR(rename->new_path)) {
            rename->new_path = NULL;
            return false;
        }
    }
    if (rename->new_path && rename->kmsg.msg.new_file.path_size) {
        rename->kmsg.msg.new_file.path_offset = rename->kmsg.hdr.payload;
        rename->kmsg.hdr.payload += rename->kmsg.msg.new_file.path_size;
    }

    return true;
}

bool fill_in_preaction_unlink(struct dynsec_event *dynsec_event,
                              struct path *path, gfp_t mode)
{
    struct dynsec_unlink_event *unlink = NULL;

    if (!dynsec_event ||
        !(dynsec_event->event_type == DYNSEC_EVENT_TYPE_UNLINK ||
          dynsec_event->event_type == DYNSEC_EVENT_TYPE_RMDIR)) {
        return false;
    }
    unlink = dynsec_event_to_unlink(dynsec_event);

    fill_in_task_ctx(&unlink->kmsg.msg.task);

    fill_in_file_data(&unlink->kmsg.msg.file, path);

    unlink->path = dynsec_build_path(path, &unlink->kmsg.msg.file, mode);
    if (unlink->path && unlink->kmsg.msg.file.path_size) {
        unlink->kmsg.msg.file.path_offset = unlink->kmsg.hdr.payload;
        unlink->kmsg.hdr.payload += unlink->kmsg.msg.file.path_size;
    }
    return true;
}


bool fill_in_preaction_symlink(struct dynsec_event *dynsec_event,
                               const char *old_name,
                               int newdfd, const char __user *newname)
{
    struct dynsec_symlink_event *symlink = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_SYMLINK) {
        return false;
    }

    symlink = dynsec_event_to_symlink(dynsec_event);

    fill_in_task_ctx(&symlink->kmsg.msg.task);

    symlink->path = build_preaction_path(newdfd, newname, 0,
                                         &symlink->kmsg.msg.file);
    if (IS_ERR(symlink->path)) {
        symlink->path = NULL;
        return false;
    }
    symlink->kmsg.msg.file.umode |= S_IFLNK;

    if (symlink->path && symlink->kmsg.msg.file.path_size) {
        symlink->kmsg.msg.file.path_offset = symlink->kmsg.hdr.payload;
        symlink->kmsg.hdr.payload += symlink->kmsg.msg.file.path_size;
    }

    if (old_name && *old_name) {
        size_t size = strlen(old_name) + 1;

        symlink->target_path = kmalloc(size, GFP_KERNEL);
        if (symlink->target_path) {
            memcpy(symlink->target_path, old_name, size);
            symlink->target_path[size - 1] = 0;
            symlink->kmsg.msg.target.size = (uint16_t)size;
            symlink->kmsg.msg.target.offset = symlink->kmsg.hdr.payload;
            symlink->kmsg.hdr.payload += symlink->kmsg.msg.target.size;
        }
    }

    return true;
}

bool fill_in_preaction_link(struct dynsec_event *dynsec_event,
                            struct path *oldpath,
                            int newdfd, const char __user *newname)
{
    struct dynsec_link_event *link = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_LINK) {
        return false;
    }

    link = dynsec_event_to_link(dynsec_event);

    fill_in_task_ctx(&link->kmsg.msg.task);

    // Should be complete info
    fill_in_file_data(&link->kmsg.msg.old_file, oldpath);


    link->old_path = dynsec_build_path(oldpath, &link->kmsg.msg.old_file,
                                       GFP_KERNEL);
    if (link->old_path && link->kmsg.msg.old_file.path_size) {
        link->kmsg.msg.old_file.path_offset = link->kmsg.hdr.payload;
        link->kmsg.hdr.payload += link->kmsg.msg.old_file.path_size;
    }

    link->new_path = build_preaction_path(newdfd, newname, 0,
                                          &link->kmsg.msg.new_file);
    if (IS_ERR(link->new_path)) {
        link->new_path = NULL;
        return false;
    }
    if (link->new_path && link->kmsg.msg.new_file.path_size) {
        link->kmsg.msg.new_file.path_offset = link->kmsg.hdr.payload;
        link->kmsg.hdr.payload += link->kmsg.msg.new_file.path_size;
    }

    return true;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
bool fill_in_preaction_setattr(struct dynsec_event *dynsec_event,
                               struct iattr *attr, struct path *path)
{
    struct dynsec_setattr_event *setattr = NULL;

    if (!dynsec_event ||
        dynsec_event->event_type != DYNSEC_EVENT_TYPE_SETATTR) {
        return false;
    }
    setattr = dynsec_event_to_setattr(dynsec_event);

    fill_in_task_ctx(&setattr->kmsg.msg.task);

    // Tell user we got likely have a filepath
    if (attr->ia_valid & ATTR_MODE) {
        setattr->kmsg.msg.attr_umode = attr->ia_mode;
        setattr->kmsg.msg.attr_mask |= ATTR_MODE;
    }
    if (attr->ia_valid & ATTR_UID) {
        setattr->kmsg.msg.attr_uid =
            from_kuid(&init_user_ns, attr->ia_uid);
        setattr->kmsg.msg.attr_mask |= ATTR_UID;
    }
    if (attr->ia_valid & ATTR_GID) {
        setattr->kmsg.msg.attr_gid =
            from_kgid(&init_user_ns, attr->ia_gid);
        setattr->kmsg.msg.attr_mask |= ATTR_GID;
    }

    // Fill in file path related info
    if (path) {
        // Tells user this is the full filepath
        fill_in_file_data(&setattr->kmsg.msg.file, path);

        // MUST Be GFP_ATOMIC
        setattr->path = dynsec_build_path(path,
                                          &setattr->kmsg.msg.file,
                                          GFP_ATOMIC);
        if (setattr->path && setattr->kmsg.msg.file.path_size) {
            setattr->kmsg.msg.file.path_offset = setattr->kmsg.hdr.payload;
            setattr->kmsg.hdr.payload += setattr->kmsg.msg.file.path_size;

            // Not truly ATTR_FILE but it's fine
            setattr->kmsg.msg.attr_mask |= ATTR_FILE;
        }
    }

    return true;
}
#endif
//#endif /* ! CONFIG_SECURITY_PATH */

static char *fill_in_task_exe(struct task_struct *task,
                              struct dynsec_file *dynsec_file, gfp_t mode)
{
    struct mm_struct *mm;
    char *exe_path = NULL;
    struct file *exe_file = NULL;

    if (!task || !dynsec_file || !task->mm || !pid_alive(task)
        || (task->flags & PF_KTHREAD)) {
        return NULL;
    }

    if (has_gfp_atomic(mode) && task->mm) {
        exe_file = task->mm->exe_file;
    } else {
        mm = get_task_mm(task);
        if (mm) {
            exe_file = dynsec_get_mm_exe_file(mm);
            mmput(mm);
        }
    }

    if (!IS_ERR_OR_NULL(exe_file)) {
        fill_in_file_data(dynsec_file, &exe_file->f_path);
        exe_path = dynsec_build_path_greedy(&exe_file->f_path,
                                            dynsec_file, mode);
        if (!has_gfp_atomic(mode)) {
            fput(exe_file);
        }
        if (IS_ERR(exe_path)) {
            exe_path = NULL;
        }
    }
    return exe_path;
}

struct dynsec_event *fill_in_dynsec_task_dump(struct task_struct *task, gfp_t mode)
{
    struct dynsec_event *dynsec_event = NULL;
    struct dynsec_task_dump_event *task_dump;
    bool is_task_alive;

    if (!task) {
        return NULL;
    }

    dynsec_event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_TASK_DUMP, 0,
                                      DYNSEC_REPORT_AUDIT, mode);
    if (!dynsec_event) {
        return NULL;
    }

    is_task_alive = pid_alive(task);
    task_dump = dynsec_event_to_task_dump(dynsec_event);

    __fill_in_task_ctx(task, is_task_alive, &task_dump->kmsg.msg.task);
    task_dump->exec_path = fill_in_task_exe(task, &task_dump->kmsg.msg.exec_file,
                                            mode);
    if (task_dump->exec_path && task_dump->kmsg.msg.exec_file.path_size) {
        task_dump->kmsg.msg.exec_file.path_offset = task_dump->kmsg.hdr.payload;
        task_dump->kmsg.hdr.payload += task_dump->kmsg.msg.exec_file.path_size;
    }
    return dynsec_event;
}
