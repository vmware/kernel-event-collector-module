// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "print.h"


#ifndef FMODE_EXEC
#define FMODE_EXEC 0x20
#endif

int debug_print = 0;


// Prints fields that are available given bitmap
static void print_dynsec_file(struct dynsec_file *file,
                              struct dynsec_file *intent)
{
    // Regular event takes priority on DYNSEC_FILE_ATTR_INODE and
    // DYNSEC_FILE_ATTR_PARENT_DEVICE.
    if (file->attr_mask & DYNSEC_FILE_ATTR_INODE) {
        printf(" ino:%lu uid:%u gid:%u umode:%#o size:%lu", file->ino,
                file->uid, file->gid, file->umode, file->size);
    } else if (intent && (intent->attr_mask & DYNSEC_FILE_ATTR_INODE)) {
        printf(" ino:%lu uid:%u gid:%u umode:%#o size:%lu", intent->ino,
                intent->uid, intent->gid, intent->umode, intent->size);
    }
    if (file->attr_mask & DYNSEC_FILE_ATTR_DEVICE) {
        printf(" dev:%#x sb_magic:%#lx", file->dev, file->sb_magic);
    } else if (intent && (intent->attr_mask & DYNSEC_FILE_ATTR_DEVICE)) {
        printf(" i-dev:%#x i-sb_magic:%#lx", intent->dev, intent->sb_magic);
    }

    // Intent takes priority on DYNSEC_FILE_ATTR_PARENT_INODE and
    // DYNSEC_FILE_ATTR_PARENT_DEVICE.
    if (intent && (intent->attr_mask & DYNSEC_FILE_ATTR_PARENT_INODE)) {
        printf(" i-parent[ino:%lu uid:%u gid:%u umode:%#o", intent->parent_ino,
               intent->parent_uid, intent->parent_gid, intent->parent_umode);
        if (intent->attr_mask & DYNSEC_FILE_ATTR_PARENT_DEVICE) {
            printf(" dev:%#x", intent->parent_dev);
        }
        printf("]");
    } else if (intent && (intent->attr_mask & DYNSEC_FILE_ATTR_PARENT_DEVICE)) {
        printf(" i-parent[dev:%#x]", intent->parent_dev);
    } else if (file->attr_mask & DYNSEC_FILE_ATTR_PARENT_INODE) {
        printf(" parent[ino:%lu uid:%u gid:%u umode:%#o", file->parent_ino,
               file->parent_uid, file->parent_gid, file->parent_umode);
        if (file->attr_mask & DYNSEC_FILE_ATTR_PARENT_DEVICE) {
            printf(" dev:%#x", file->parent_dev);
        }
        printf("]");
    } else if (file->attr_mask & DYNSEC_FILE_ATTR_PARENT_DEVICE) {
        printf(" parent[dev:%#x]", file->parent_dev);
    }
}

static void print_path(const char *start, struct dynsec_file *file,
                       const char *intent_start, struct dynsec_file *intent)
{
    if (file->path_offset) {
        const char *path = start + file->path_offset;
        const char *path_type = "";
        const char *intent_path = NULL;
        const char *intent_path_type = "";

        if (file->attr_mask & DYNSEC_FILE_ATTR_PATH_FULL) {
            path_type = "fullpath";
        } else if (file->attr_mask & DYNSEC_FILE_ATTR_PATH_DENTRY) {
            path_type = "dentrypath";
        } else if (file->attr_mask & DYNSEC_FILE_ATTR_PATH_RAW) {
            path_type = "rawpath";
        }

        if (intent && intent_start && intent->path_offset) {
            intent_path = intent_start + intent->path_offset;
            if (intent->attr_mask & DYNSEC_FILE_ATTR_PATH_FULL) {
                intent_path_type = "i-fullpath";
            }   else if (file->attr_mask & DYNSEC_FILE_ATTR_PATH_DENTRY) {
                intent_path_type = "i-dentrypath";
            } else if (file->attr_mask & DYNSEC_FILE_ATTR_PATH_RAW) {
                intent_path_type = "i-rawpath";
            }
        }

        // Select the intent's path if the regular event's
        // path is weaker.
        if (!(file->attr_mask & DYNSEC_FILE_ATTR_PATH_FULL) &&
            intent_path && (intent->attr_mask & DYNSEC_FILE_ATTR_PATH_FULL)) {
            printf(" %s:'%s'", intent_path_type, intent_path);
            if (debug_print) {
                printf(" %s:'%s'", path_type, path);
            }
        } else {
            printf(" %s:'%s'", path_type, path);
        }
    }
}

static void print_task_ctx(struct dynsec_task_ctx *task_ctx)
{
    if (!task_ctx) {
        return;
    }
    printf("start_time:%c%lu",
           (task_ctx->extra_ctx & DYNSEC_TASK_IMPRECISE_START_TIME) ?
           '?' : '+', task_ctx->start_time
    );
    if (task_ctx->tid != task_ctx->pid) {
        printf(" tid:%u", task_ctx->tid);
    }
    printf(" pid:%u ppid:%u mnt_ns:%u ctx:%#x",
           task_ctx->pid, task_ctx->ppid,
           task_ctx->mnt_ns,
           task_ctx->extra_ctx);
    if (task_ctx->uid == task_ctx->euid) {
        printf(" uid:%u", task_ctx->uid);
    } else {
        printf(" uid:%u euid:%u", task_ctx->uid, task_ctx->euid);
    }
    if (task_ctx->gid == task_ctx->egid) {
        printf(" gid:%u", task_ctx->gid);
    } else {
        printf(" gid:%u egid:%u", task_ctx->gid, task_ctx->egid);
    }
}

void print_exec_event(struct local_dynsec_event *event)
{
    struct dynsec_exec_umsg *exec_msg = (struct dynsec_exec_umsg *)event->hdr;
    const char *ev_str = "EXEC";
    const char *start = (const char *)exec_msg;


    printf("%s: tid:%u mnt_ns:%u req_id:%lu ", ev_str,
           exec_msg->hdr.tid, exec_msg->msg.task.mnt_ns,
           exec_msg->hdr.req_id);
    print_dynsec_file(&exec_msg->msg.file, NULL);
    print_path(start, &exec_msg->msg.file, NULL, NULL);
    printf("\n");
}

void print_unlink_event(struct local_dynsec_event *event)
{
    struct dynsec_unlink_umsg *unlink_msg = (struct dynsec_unlink_umsg *)event->hdr;
    struct dynsec_unlink_umsg *intent = NULL;
    const char *ev_str = "UNLINK";
    const char *start = (const char *)unlink_msg;
    const char *intent_str = "";
    const char *intent_start = NULL;

    if (unlink_msg->hdr.event_type == DYNSEC_EVENT_TYPE_RMDIR)
        ev_str = "RMDIR";

    if (unlink_msg->hdr.report_flags & DYNSEC_REPORT_INTENT) {
        intent_str = "-INTENT";
    }

    if (event->intent) {
        if (event->intent->event_type == unlink_msg->hdr.event_type) {
            intent = (struct dynsec_unlink_umsg *)event->intent;
            intent_start = (const char *)event->intent;
        } else if (debug_print) {
            fprintf(stderr, "Wrong intent type!\n");
        }
    }

    printf("%s%s: tid:%u mnt_ns:%u req_id:%lu", ev_str, intent_str,
           unlink_msg->hdr.tid, unlink_msg->msg.task.mnt_ns,
           unlink_msg->hdr.req_id);

    if (unlink_msg->hdr.report_flags & DYNSEC_REPORT_INTENT_FOUND) {
        printf(" intent_req_id:%lu", unlink_msg->hdr.intent_req_id);
    }
    print_dynsec_file(&unlink_msg->msg.file,
                      intent ? &intent->msg.file: NULL);
    print_path(start, &unlink_msg->msg.file,
               intent_start, intent ? &intent->msg.file: NULL);
    printf("\n");
}

void print_rename_event(struct local_dynsec_event *event)
{
    struct dynsec_rename_umsg *rename_msg = (struct dynsec_rename_umsg *)event->hdr;
    struct dynsec_rename_umsg *intent = NULL;
    const char *start = (const char *)rename_msg;
    const char *intent_str = "";
    const char *intent_start = NULL;

    if (rename_msg->hdr.report_flags & DYNSEC_REPORT_INTENT) {
        intent_str = "-INTENT";
    }

    if (event->intent) {
        if (event->intent->event_type == rename_msg->hdr.event_type) {
            intent = (struct dynsec_rename_umsg *)event->intent;
            intent_start = (const char *)event->intent;
        } else if (debug_print) {
            fprintf(stderr, "Wrong intent type!\n");
        }
    }

    printf("RENAME%s: tid:%u mnt_ns:%u req_id:%lu", intent_str,
           rename_msg->hdr.tid, rename_msg->msg.task.mnt_ns,
           rename_msg->hdr.req_id);

    if (rename_msg->hdr.report_flags & DYNSEC_REPORT_INTENT_FOUND) {
        printf(" intent_req_id:%lu", rename_msg->hdr.intent_req_id);
    }
    printf(" OLD{");
    print_dynsec_file(&rename_msg->msg.old_file,
                      intent ? &intent->msg.old_file: NULL);
    print_path(start, &rename_msg->msg.old_file,
               intent_start, intent ? &intent->msg.old_file: NULL);
    printf("} -> NEW{");
    print_dynsec_file(&rename_msg->msg.new_file,
                      intent ? &intent->msg.new_file: NULL);
    print_path(start, &rename_msg->msg.new_file,
               intent_start, intent ? &intent->msg.new_file: NULL);
    printf("}\n");
}

void print_setattr_event(struct local_dynsec_event *event)
{
    struct dynsec_setattr_umsg *setattr = (struct dynsec_setattr_umsg *)event->hdr;
    struct dynsec_setattr_umsg *intent = NULL;
    const char *start = (const char *)setattr;
    const char *intent_str = "";
    const char *intent_start = NULL;


    if (setattr->hdr.report_flags & DYNSEC_REPORT_INTENT) {
        intent_str = "-INTENT";
    }

    if (event->intent) {
        // May want to compare attr_mask too?
        if (event->intent->event_type == setattr->hdr.event_type) {
            intent = (struct dynsec_setattr_umsg *)event->intent;
            intent_start = (const char *)event->intent;
        } else if (debug_print) {
            fprintf(stderr, "Wrong intent type!\n");
        }
    }

    printf("SETATTR%s: tid:%u mnt_ns:%u req_id:%lu", intent_str,
           setattr->hdr.tid, setattr->msg.task.mnt_ns,
           setattr->hdr.req_id);
    if (setattr->hdr.report_flags & DYNSEC_REPORT_INTENT_FOUND) {
        printf(" intent_req_id:%lu", setattr->hdr.intent_req_id);
    }
    if (setattr->msg.attr_mask & DYNSEC_SETATTR_MODE) {
        printf(" chmod umode[%o -> %o]", setattr->msg.file.umode,
               setattr->msg.attr_umode);
    }
    if (setattr->msg.attr_mask & DYNSEC_SETATTR_UID) {
        printf(" chown uid[%u -> %u]", setattr->msg.file.uid,
               setattr->msg.attr_uid);
    }
    if (setattr->msg.attr_mask & DYNSEC_SETATTR_GID) {
        printf(" chown gid[%u -> %u]", setattr->msg.file.gid,
               setattr->msg.attr_gid);
    }
    if (setattr->msg.attr_mask & DYNSEC_SETATTR_SIZE) {
        const char *size_chg = "trunc";
        if (setattr->msg.attr_size > setattr->msg.file.size)
            size_chg = "falloc";
        printf(" %s[%lu -> %lu how:%s]", size_chg,
               setattr->msg.file.size, setattr->msg.attr_size,
               (setattr->msg.attr_mask & DYNSEC_SETATTR_OPEN) ?
                    "open(O_TRUNC)" : "truncate()");
    }

    print_dynsec_file(&setattr->msg.file,
                      intent ? &intent->msg.file: NULL);
    print_path(start, &setattr->msg.file,
               intent_start, intent ? &intent->msg.file: NULL);
    printf("\n");
}



void print_create_event(struct local_dynsec_event *event)
{
    struct dynsec_create_umsg *create = (struct dynsec_create_umsg *)event->hdr;
    struct dynsec_create_umsg *intent = NULL;
    const char *ev_str = "CREATE";
    const char *intent_str = "";
    const char *start = (const char *)create;
    const char *intent_start = NULL;

    if (create->hdr.event_type == DYNSEC_EVENT_TYPE_MKDIR)
        ev_str = "MDKIR";

    if (create->hdr.report_flags & DYNSEC_REPORT_INTENT) {
        intent_str = "-INTENT";
    }

    if (event->intent) {
        if (event->intent->event_type == create->hdr.event_type) {
            intent = (struct dynsec_create_umsg *)event->intent;
            intent_start = (const char *)event->intent;
        } else if (debug_print) {
            fprintf(stderr, "Wrong intent type!\n");
        }
    }

    printf("%s%s: tid:%u mnt_ns:%u req_id:%lu", ev_str, intent_str,
           create->hdr.tid, create->msg.task.mnt_ns, create->hdr.req_id);
    if (create->hdr.report_flags & DYNSEC_REPORT_INTENT_FOUND) {
        printf(" intent_req_id:%lu", create->hdr.intent_req_id);
    }

    print_dynsec_file(&create->msg.file,
                      intent ? &intent->msg.file: NULL);
    print_path(start, &create->msg.file,
               intent_start, intent ? &intent->msg.file: NULL);
    printf("\n");
}

void print_open_event(struct local_dynsec_event *event)
{
    struct dynsec_file_umsg *file = (struct dynsec_file_umsg *)event->hdr;
    const char *path = "";
    const char *ev_str = "OPEN";
    const char *start = (const char *)file;

    if (file->hdr.event_type == DYNSEC_EVENT_TYPE_CLOSE)
        ev_str = "CLOSE";

    if (file->msg.file.path_offset) {
        path = start + file->msg.file.path_offset;
    }

    printf("%s: tid:%u ino:%lu dev:%#x mnt_ns:%u f_mode:%#010x f_flags:%#010x magic:%#lx uid:%u"
        " '%s'\n", ev_str,
        file->hdr.tid, file->msg.file.ino, file->msg.file.dev,
        file->msg.task.mnt_ns, file->msg.f_mode, file->msg.f_flags,
        file->msg.file.sb_magic,
        file->msg.task.uid, path);
}

void print_mmap_event(struct local_dynsec_event *event)
{
    struct dynsec_mmap_umsg *mmap = (struct dynsec_mmap_umsg *)event->hdr;
    const char *path = "";
    const char *ev_str = "MMAP";
    const char *start = (const char *)mmap;

    if (mmap->msg.task.extra_ctx & DYNSEC_TASK_IN_EXECVE ||
        (mmap->msg.f_flags & FMODE_EXEC) == FMODE_EXEC) {

        if (mmap->msg.mmap_flags & MAP_EXECUTABLE) {
            ev_str = "MMAP_EXEC";
        } else {
            ev_str = "MMAP_LDSO";
        }
    } else if (mmap->msg.mmap_flags & MAP_EXECUTABLE) {
        ev_str = "MMAP_EXEC";
    }

    if (mmap->msg.file.path_offset) {
        path = start + mmap->msg.file.path_offset;
    }

    printf("%s: tid:%u ino:%lu dev:%#x '%s' mnt_ns:%u magic:%#lx uid:%u\n",
           ev_str, mmap->hdr.tid, mmap->msg.file.ino, mmap->msg.file.dev, path,
           mmap->msg.task.mnt_ns, mmap->msg.file.sb_magic, mmap->msg.task.uid);
}

void print_link_event(struct local_dynsec_event *event)
{
    struct dynsec_link_umsg *link_msg = (struct dynsec_link_umsg *)event->hdr;
    struct dynsec_link_umsg *intent = NULL;
    const char *start = (const char *)link_msg;
    const char *intent_str = "";
    const char *intent_start = NULL;

    if (link_msg->hdr.report_flags & DYNSEC_REPORT_INTENT) {
        intent_str = "-INTENT";
    }

    if (event->intent) {
        if (event->intent->event_type == link_msg->hdr.event_type) {
            intent = (struct dynsec_link_umsg *)event->intent;
            intent_start = (const char *)event->intent;
        } else if (debug_print) {
            fprintf(stderr, "Wrong intent type!\n");
        }
    }

    printf("LINK%s: tid:%u mnt_ns:%u req_id:%lu", intent_str,
           link_msg->hdr.tid, link_msg->msg.task.mnt_ns,
           link_msg->hdr.req_id);

    if (link_msg->hdr.report_flags & DYNSEC_REPORT_INTENT_FOUND) {
        printf(" intent_req_id:%lu", link_msg->hdr.intent_req_id);
    }
    printf(" OLD{");
    print_dynsec_file(&link_msg->msg.old_file,
                      intent ? &intent->msg.old_file: NULL);
    print_path(start, &link_msg->msg.old_file,
               intent_start, intent ? &intent->msg.old_file: NULL);
    printf("} -> NEW{");
    print_dynsec_file(&link_msg->msg.new_file,
                      intent ? &intent->msg.new_file: NULL);
    print_path(start, &link_msg->msg.new_file,
               intent_start, intent ? &intent->msg.new_file: NULL);
    printf("}\n");
}

void print_symlink_event(struct local_dynsec_event *event)
{
    struct dynsec_symlink_umsg *symlink = (struct dynsec_symlink_umsg *)event->hdr;
    struct dynsec_symlink_umsg *intent = NULL;
    const char *intent_str = "";
    const char *target_path = "";
    const char *start = (const char *)symlink;
    const char *intent_start = NULL;

    if (symlink->msg.target.offset) {
        target_path = start + symlink->msg.target.offset;
    }
    if (symlink->hdr.report_flags & DYNSEC_REPORT_INTENT) {
        intent_str = "-INTENT";
    }

    if (event->intent) {
        if (event->intent->event_type == symlink->hdr.event_type) {
            intent = (struct dynsec_symlink_umsg *)event->intent;
            intent_start = (const char *)event->intent;
        } else if (debug_print) {
            fprintf(stderr, "Wrong intent type!\n");
        }
    }

    printf("SYMLINK%s: tid:%u mnt_ns:%u req_id:%lu", intent_str,
           symlink->hdr.tid, symlink->msg.task.mnt_ns, symlink->hdr.req_id);
    if (symlink->hdr.report_flags & DYNSEC_REPORT_INTENT_FOUND) {
        printf(" intent_req_id:%lu", symlink->hdr.intent_req_id);
    }
    print_dynsec_file(&symlink->msg.file,
                      intent ? &intent->msg.file : NULL);
    print_path(start, &symlink->msg.file,
               intent_start, intent ? &intent->msg.file : NULL);
    printf(" -> target:'%s'\n", target_path);
}

void print_task_event(struct local_dynsec_event *event)
{
    struct dynsec_task_umsg *task_msg = (struct dynsec_task_umsg *)event->hdr;
    const char *ev_str = "EXIT";
    const char *start = (const char *)task_msg;

    if (task_msg->hdr.hook_type == DYNSEC_TP_HOOK_TYPE_TASK_FREE ||
        task_msg->hdr.hook_type == DYNSEC_HOOK_TYPE_TASK_FREE) {
        ev_str = "TASK_FREE";
    }
    else if (task_msg->hdr.event_type == DYNSEC_EVENT_TYPE_CLONE)
        ev_str = "FORK";

    printf("%s: ", ev_str);
    print_task_ctx(&task_msg->msg.task);
    if (task_msg->hdr.event_type == DYNSEC_EVENT_TYPE_CLONE) {
        if (task_msg->msg.exec_file.attr_mask) {
            print_dynsec_file(&task_msg->msg.exec_file, NULL);
            print_path(start, &task_msg->msg.exec_file, NULL, NULL);
        }
    }
    printf("\n");
}

void print_ptrace_event(struct local_dynsec_event *event)
{
    struct dynsec_ptrace_umsg *ptrace = (struct dynsec_ptrace_umsg *)event->hdr;

    printf("PTRACE: source:{");
    print_task_ctx(&ptrace->msg.source);
    printf("} -> target{");
    print_task_ctx(&ptrace->msg.target);
    printf("}\n");
}

void print_signal_event(struct local_dynsec_event *event)
{
    struct dynsec_signal_umsg *signal = (struct dynsec_signal_umsg *)event->hdr;

    printf("SIGNAL: sig:%d source:{", signal->msg.signal);
    print_task_ctx(&signal->msg.source);
    printf("} -> target{");
    print_task_ctx(&signal->msg.target);
    printf("}\n");
}

void print_task_dump_event(struct local_dynsec_event *event)
{
    struct dynsec_task_dump_umsg *task_dump = (struct dynsec_task_dump_umsg *)event->hdr;
    const char *start = (const char *)task_dump;

    printf("TASK_DUMP: ");
    print_task_ctx(&task_dump->msg.task);
    print_dynsec_file(&task_dump->msg.exec_file, NULL);
    print_path(start, &task_dump->msg.exec_file, NULL, NULL);
    printf("\n");
}

void print_event(struct local_dynsec_event *event)
{
    if (!event || !event->hdr) {
        return;
    }

    switch (event->hdr->event_type) {
    case DYNSEC_EVENT_TYPE_EXEC:
        print_exec_event(event);
        break;

    case DYNSEC_EVENT_TYPE_UNLINK:
    case DYNSEC_EVENT_TYPE_RMDIR:
        print_unlink_event(event);
        break;

    case DYNSEC_EVENT_TYPE_RENAME:
        print_rename_event(event);
        break;

    case DYNSEC_EVENT_TYPE_SETATTR:
        print_setattr_event(event);
        break;

    case DYNSEC_EVENT_TYPE_CREATE:
    case DYNSEC_EVENT_TYPE_MKDIR:
        print_create_event(event);
        break;

    case DYNSEC_EVENT_TYPE_OPEN:
    case DYNSEC_EVENT_TYPE_CLOSE:
        print_open_event(event);
        break;

    case DYNSEC_EVENT_TYPE_MMAP:
        print_mmap_event(event);
        break;

    case DYNSEC_EVENT_TYPE_LINK:
        print_link_event(event);
        break;

    case DYNSEC_EVENT_TYPE_SYMLINK:
        print_symlink_event(event);
        break;

    case DYNSEC_EVENT_TYPE_CLONE:
    case DYNSEC_EVENT_TYPE_EXIT:
        print_task_event(event);
        break;

    case DYNSEC_EVENT_TYPE_PTRACE:
        print_ptrace_event(event);
        break;

    case DYNSEC_EVENT_TYPE_SIGNAL:
        print_signal_event(event);
        break;

    case DYNSEC_EVENT_TYPE_TASK_DUMP:
        print_task_dump_event(event);
        break;

    default:
        printf("UNKNOWN: hdr->tid:%u hdr->payload:%u hdr->req_id:%lu hdr->event_type:%u\n",
               event->hdr->tid, event->hdr->payload, event->hdr->req_id, event->hdr->event_type);
        break;
    }
}

void print_event_raw(struct dynsec_msg_hdr *hdr)
{
    struct local_dynsec_event event = {
        .hdr = hdr,
        .intent = NULL,
    };

    print_event(&event);
}

const char *event_type_name(enum dynsec_event_type event_type)
{
    static const char *UNKNOWN = "UNKNOWN";
    static const char *name_map[DYNSEC_EVENT_TYPE_MAX] = {
        [DYNSEC_EVENT_TYPE_EXEC] = "EXEC",
        [DYNSEC_EVENT_TYPE_RENAME] = "RENAME",
        [DYNSEC_EVENT_TYPE_UNLINK] = "UNLINK",
        [DYNSEC_EVENT_TYPE_RMDIR] = "RMDIR",
        [DYNSEC_EVENT_TYPE_MKDIR] = "MKDIR",
        [DYNSEC_EVENT_TYPE_CREATE] = "CREATE",
        [DYNSEC_EVENT_TYPE_SETATTR] = "SETATTR",
        [DYNSEC_EVENT_TYPE_OPEN] = "OPEN",
        [DYNSEC_EVENT_TYPE_CLOSE] = "CLOSE",
        [DYNSEC_EVENT_TYPE_LINK] = "LINK",
        [DYNSEC_EVENT_TYPE_SYMLINK] = "SYMLINK",
        [DYNSEC_EVENT_TYPE_SIGNAL] = "SIGNAL",
        [DYNSEC_EVENT_TYPE_PTRACE] = "PTRACE",
        [DYNSEC_EVENT_TYPE_MMAP] = "MMAP",
        [DYNSEC_EVENT_TYPE_CLONE] = "CLONE",
        [DYNSEC_EVENT_TYPE_EXIT] = "EXIT",
        [DYNSEC_EVENT_TYPE_TASK_DUMP] = "TASK_DUMP",
        // Special Events
        [DYNSEC_EVENT_TYPE_HEALTH] = "HEALTH",
        [DYNSEC_EVENT_TYPE_GENERIC_AUDIT] = "AUDIT",
        [DYNSEC_EVENT_TYPE_GENERIC_DEBUG] = "DEBUG",
    };
    if (event_type < DYNSEC_EVENT_TYPE_EXEC ||
        event_type >= DYNSEC_EVENT_TYPE_MAX) {
        return UNKNOWN;
    }
    return name_map[event_type];
}
