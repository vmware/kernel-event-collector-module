// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <signal.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>

#include "dynsec.h"

#ifndef FMODE_EXEC
#define FMODE_EXEC 0x20
#endif

static int quiet = 0;
static int quiet_open_events = 1;
static uint32_t default_cache_flags = 0;

unsigned int largest_read = 0;
int max_parsed_per_read = 0;
int max_bytes_per_event = 0;
unsigned long long total_events = 0;
unsigned long long total_bytes_read = 0;
unsigned long long total_reads = 0;
unsigned long long total_stall_events = 0;
unsigned long long total_nonstall_events = 0;
unsigned long long total_cached_stall_events = 0;
unsigned long long *histo_reads = NULL;
unsigned long long *histo_event_type = NULL;
#define MAX_BUF_SZ (1 << 15)
#define EVENT_AVG_SZ (1 << 7)
#define MAX_HISTO_SZ (MAX_BUF_SZ / EVENT_AVG_SZ)
char *global_buf;

// gcc -I../../include -pthread ./dynsec_dev.c -o dynsec

// Pass in the desired char device and the major number
// That can be grabbed from /proc/devices

static int create_chrdev(unsigned int major_num, unsigned int minor,
                         const char *dev_path)
{
    dev_t dev = 0;
    int ret;

    if (!dev_path) {
        return -EINVAL;
    }

    dev = makedev(major_num, 0);

    ret = mknod(dev_path, S_IFCHR|S_IRUSR|S_IWUSR, dev);
    if (!ret || (ret < 0 && errno == EEXIST)) {
        ret = open(dev_path, O_RDWR | O_CLOEXEC);
        if (ret < 0) {
            fprintf(stderr, "Unable to open(%s,O_RDWR| O_CLOEXEC) = %m\n",
                    dev_path);
        }
    }

    return ret;
}

int respond_to_access_request(int fd, struct dynsec_msg_hdr *hdr,
                              int response_type)
{
    ssize_t ret;
    struct dynsec_response response = {
        .req_id = hdr->req_id,
        .event_type = hdr->event_type,
        .tid = hdr->tid,
        .response = response_type,
        .cache_flags = default_cache_flags,
    };

    // switch(hdr->event_type)
    // {
    // // rm -rf
    // case DYNSEC_EVENT_TYPE_UNLINK:
    //     // Should periodically get evicted/unset
    //     // if RMDIR events enabled
    //     response.cache_flags = DYNSEC_CACHE_CLEAR_ON_EVENT;
    //     break;

    // // tar -xf
    // case DYNSEC_EVENT_TYPE_CREATE:
    // case DYNSEC_EVENT_TYPE_SETATTR:
    //     response.cache_flags = DYNSEC_CACHE_ENABLE_EXCL;
    //     break;

    // case DYNSEC_EVENT_TYPE_OPEN:
    // case DYNSEC_EVENT_TYPE_EXEC:
    //     response.cache_flags = DYNSEC_CACHE_CLEAR_ON_EVENT;
    //     break;
    // }

    ret = write(fd, &response, sizeof(response));
    if (ret < 0) {
        return -errno;
    }
    if (ret != sizeof(response)) {
        return (int)ret;
    }
    return 0;
}


void print_exec_event(int fd, struct dynsec_exec_umsg *exec_msg, const char *banned_path)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *path = "";
    const char *ev_str = "EXEC";
    const char *start = (const char *)exec_msg;

    if (exec_msg->msg.file.path_offset) {
        path = start + exec_msg->msg.file.path_offset;
    }

    // Ban some matching substring
    if (exec_msg->hdr.report_flags & DYNSEC_REPORT_STALL) {
        if (banned_path && *banned_path && path && *path &&
            strstr(path, banned_path)) {
            response = DYNSEC_RESPONSE_EPERM;
            ev_str = "EXEC DENIED:";
        }
    }
    if (exec_msg->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &exec_msg->hdr, response);

    if (quiet) return;

    printf("%s: tid:%u ino:%llu dev:%#x mnt_ns:%u magic:%#lx uid:%u '%s' filesize:%llu\n",
        ev_str, exec_msg->msg.task.tid, exec_msg->msg.file.ino, exec_msg->msg.file.dev,
        exec_msg->msg.task.mnt_ns, exec_msg->msg.file.sb_magic, exec_msg->msg.task.uid, path,
        exec_msg->msg.file.size
    );
}

void print_unlink_event(int fd, struct dynsec_unlink_umsg *unlink_msg)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *path = "";
    const char *ev_str = "UNLINK";
    const char *start = (const char *)unlink_msg;

    if (unlink_msg->hdr.event_type == DYNSEC_EVENT_TYPE_RMDIR)
        ev_str = "RMDIR";

    if (unlink_msg->msg.file.path_offset) {
        path = start + unlink_msg->msg.file.path_offset;
    }

    if (unlink_msg->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &unlink_msg->hdr, response);

    if (quiet) return;

    printf("%s: tid:%u ino:%llu dev:%#x mnt_ns:%u umode:%#o magic:%#lx uid:%u "
        "parent_ino:%llu '%s'\n", ev_str,
        unlink_msg->hdr.tid, unlink_msg->msg.file.ino, unlink_msg->msg.file.dev,
        unlink_msg->msg.task.mnt_ns, unlink_msg->msg.file.umode, unlink_msg->msg.file.sb_magic,
        unlink_msg->msg.task.uid, unlink_msg->msg.file.parent_ino, path);
}

void print_rename_event(int fd, struct dynsec_rename_umsg *rename_msg)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *old_path = "";
    const char *new_path = "";
    const char *start = (const char *)rename_msg;

    if (rename_msg->msg.old_file.path_offset) {
        old_path = start + rename_msg->msg.old_file.path_offset;
    }
    if (rename_msg->msg.new_file.path_offset) {
        new_path = start + rename_msg->msg.new_file.path_offset;
    }

    if (rename_msg->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &rename_msg->hdr, response);

    if (quiet) return;

    printf("RENAME: tid:%u dev:%#x mnt_ns:%u magic:%#lx uid:%u "
        "'%s'[%llu %#o %llu]->'%s'[%llu %#o %llu]\n",
        rename_msg->hdr.tid, rename_msg->msg.old_file.dev, rename_msg->msg.task.mnt_ns,
        rename_msg->msg.old_file.sb_magic,
        rename_msg->msg.task.uid,
        old_path, rename_msg->msg.old_file.ino, rename_msg->msg.old_file.umode,
        rename_msg->msg.old_file.parent_ino,

        new_path, rename_msg->msg.new_file.ino, rename_msg->msg.new_file.umode,
        rename_msg->msg.new_file.parent_ino
    );
}

void print_setattr_event(int fd, struct dynsec_setattr_umsg *setattr)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *path = "";
    const char *start = (const char *)setattr;
    const char *path_type = "";

    if (setattr->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &setattr->hdr, response);

    if (quiet) return;

    printf("SETATTR: tid:%u mask:%08x mnt_ns:%u", setattr->hdr.tid,
           setattr->msg.attr_mask, setattr->msg.task.mnt_ns);
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
        printf(" %s[%llu -> %llu how:%s]", size_chg,
               setattr->msg.file.size, setattr->msg.attr_size,
               (setattr->msg.attr_mask & DYNSEC_SETATTR_OPEN) ?
                    "open(O_TRUNC)" : "truncate()");
    }
    if (setattr->msg.file.path_offset) {
        path = start + setattr->msg.file.path_offset;
        if (setattr->msg.attr_mask & DYNSEC_SETATTR_FILE) {
            path_type = "fullpath";
        } else {
            path_type = "dentrypath";
        }
    }
    printf(" ino:%llu dev:%#x %s:%s\n", setattr->msg.file.ino,
           setattr->msg.file.dev, path_type, path);
}

void print_create_event(int fd, struct dynsec_create_umsg *create)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *path = "";
    const char *ev_str = "CREATE";
    const char *start = (const char *)create;

    if (create->hdr.event_type == DYNSEC_EVENT_TYPE_MKDIR)
        ev_str = "MDKIR";

    if (create->msg.file.path_offset) {
        path = start + create->msg.file.path_offset;
    }

    if (create->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &create->hdr, response);

    if (quiet) return;

    printf("%s: tid:%u ino:%llu dev:%#x mnt_ns:%u umode:%#o magic:%#lx uid:%u "
        "parent_ino:%llu '%s'\n", ev_str,
        create->hdr.tid, create->msg.file.ino, create->msg.file.dev,
        create->msg.task.mnt_ns, create->msg.file.umode,
        create->msg.file.sb_magic,
        create->msg.task.uid, create->msg.file.parent_ino, path);
}

void print_open_event(int fd, struct dynsec_file_umsg *file)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *path = "";
    const char *ev_str = "OPEN";
    const char *start = (const char *)file;

    if (file->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &file->hdr, response);

    if (quiet || quiet_open_events) return;

    if (file->hdr.event_type == DYNSEC_EVENT_TYPE_CLOSE)
        ev_str = "CLOSE";

    if (file->msg.file.path_offset) {
        path = start + file->msg.file.path_offset;
    }

    printf("%s: tid:%u ino:%llu dev:%#x mnt_ns:%u f_mode:%#010x f_flags:%#010x magic:%#lx uid:%u"
        " '%s'\n", ev_str,
        file->hdr.tid, file->msg.file.ino, file->msg.file.dev,
        file->msg.task.mnt_ns, file->msg.f_mode, file->msg.f_flags,
        file->msg.file.sb_magic,
        file->msg.task.uid, path);
}

void print_mmap_event(int fd, struct dynsec_mmap_umsg *mmap)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *path = "";
    const char *ev_str = "MMAP";
    const char *start = (const char *)mmap;

    if (mmap->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &mmap->hdr, response);

    if (quiet) return;

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

    printf("%s: tid:%u ino:%llu dev:%#x '%s' mnt_ns:%u magic:%#lx uid:%u\n",
           ev_str, mmap->hdr.tid, mmap->msg.file.ino, mmap->msg.file.dev, path,
           mmap->msg.task.mnt_ns, mmap->msg.file.sb_magic, mmap->msg.task.uid);
}

void print_link_event(int fd, struct dynsec_link_umsg *link_msg)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *old_path = "";
    const char *new_path = "";
    const char *start = (const char *)link_msg;

    if (link_msg->msg.old_file.path_offset) {
        old_path = start + link_msg->msg.old_file.path_offset;
    }
    if (link_msg->msg.new_file.path_offset) {
        new_path = start + link_msg->msg.new_file.path_offset;
    }

    if (link_msg->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &link_msg->hdr, response);

    if (quiet) return;

    printf("LINK: tid:%u dev:%#x mnt_ns:%u magic:%#lx uid:%u "
        "'%s'[%llu %#o %llu]->'%s'[%llu %#o %llu]\n",
        link_msg->hdr.tid, link_msg->msg.old_file.dev, link_msg->msg.task.mnt_ns,
        link_msg->msg.old_file.sb_magic,
        link_msg->msg.task.uid,
        old_path, link_msg->msg.old_file.ino, link_msg->msg.old_file.umode,
        link_msg->msg.old_file.parent_ino,

        new_path, link_msg->msg.new_file.ino, link_msg->msg.new_file.umode,
        link_msg->msg.new_file.parent_ino
    );
}

void print_symlink_event(int fd, struct dynsec_symlink_umsg *symlink)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *path = "";
    const char *target_path = "";
    const char *start = (const char *)symlink;

    if (symlink->msg.file.path_offset) {
        path = start + symlink->msg.file.path_offset;
    }
    if (symlink->msg.target.offset) {
        target_path = start + symlink->msg.target.offset;
    }

    if (symlink->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &symlink->hdr, response);

    if (quiet) return;

    printf("SYMLINK: tid:%u dev:%#x mnt_ns:%u magic:%#lx uid:%u "
        "'%s'[%llu %#o %llu]->'%s'\n",
        symlink->hdr.tid, symlink->msg.file.dev, symlink->msg.task.mnt_ns,
        symlink->msg.file.sb_magic,
        symlink->msg.task.uid,
        path, symlink->msg.file.ino, symlink->msg.file.umode,
        symlink->msg.file.parent_ino,
        target_path
    );
}

void print_task_event(int fd, struct dynsec_task_umsg *task_msg)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *ev_str = "EXIT";
    const char *start = (const char *)task_msg;


    if (task_msg->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &task_msg->hdr, response);

    if (quiet) return;

    if (task_msg->hdr.hook_type == DYNSEC_TP_HOOK_TYPE_TASK_FREE ||
        task_msg->hdr.hook_type == DYNSEC_HOOK_TYPE_TASK_FREE) {
        ev_str = "TASK_FREE";
    }
    else if (task_msg->hdr.event_type == DYNSEC_EVENT_TYPE_CLONE)
        ev_str = "FORK";

    printf("%s: %llu pid:%u ppid:%u mnt_ns:%u uid:%u\n", ev_str,
        task_msg->msg.task.start_time,
        task_msg->msg.task.pid,
        task_msg->msg.task.ppid,
        task_msg->msg.task.mnt_ns,
        task_msg->msg.task.uid
    );
}

void print_ptrace_event(int fd, struct dynsec_ptrace_umsg *ptrace)
{
    int response = DYNSEC_RESPONSE_ALLOW;

    if (ptrace->hdr.report_flags & DYNSEC_REPORT_STALL) {
        respond_to_access_request(fd, &ptrace->hdr, response);
    }

    if (quiet) return;

    printf("PTRACE: source:%u -> target:%u\n",
        ptrace->msg.source.tid, ptrace->msg.target.tid
    );
}

void print_signal_event(int fd, struct dynsec_signal_umsg *signal)
{
    int response = DYNSEC_RESPONSE_ALLOW;

    if (signal->hdr.report_flags & DYNSEC_REPORT_STALL) {
        respond_to_access_request(fd, &signal->hdr, response);
    }

    if (quiet) return;

    printf("SIGNAL: source:%u -> target:%u sig:%d\n",
        signal->msg.source.tid, signal->msg.target.tid, signal->msg.signal
    );
}

void print_event(int fd, struct dynsec_msg_hdr *hdr, const char *banned_path)
{
    int response = DYNSEC_RESPONSE_ALLOW;

    switch (hdr->event_type) {
    case DYNSEC_EVENT_TYPE_EXEC:
        print_exec_event(fd, (struct dynsec_exec_umsg *)hdr, banned_path);
        break;

    case DYNSEC_EVENT_TYPE_UNLINK:
    case DYNSEC_EVENT_TYPE_RMDIR:
        print_unlink_event(fd, (struct dynsec_unlink_umsg *)hdr);
        break;

    case DYNSEC_EVENT_TYPE_RENAME:
        print_rename_event(fd, (struct dynsec_rename_umsg *)hdr);
        break;

    case DYNSEC_EVENT_TYPE_SETATTR:
        print_setattr_event(fd, (struct dynsec_setattr_umsg *)hdr);
        break;

    case DYNSEC_EVENT_TYPE_CREATE:
    case DYNSEC_EVENT_TYPE_MKDIR:
        print_create_event(fd, (struct dynsec_create_umsg *)hdr);
        break;

    case DYNSEC_EVENT_TYPE_OPEN:
    case DYNSEC_EVENT_TYPE_CLOSE:
        print_open_event(fd, (struct dynsec_file_umsg *)hdr);
        break;

    case DYNSEC_EVENT_TYPE_MMAP:
        print_mmap_event(fd, (struct dynsec_mmap_umsg *)hdr);
        break;

    case DYNSEC_EVENT_TYPE_LINK:
        print_link_event(fd, (struct dynsec_link_umsg *)hdr);
        break;

    case DYNSEC_EVENT_TYPE_SYMLINK:
        print_symlink_event(fd, (struct dynsec_symlink_umsg *)hdr);
        break;

    case DYNSEC_EVENT_TYPE_CLONE:
    case DYNSEC_EVENT_TYPE_EXIT:
        print_task_event(fd, (struct dynsec_task_umsg *)hdr);
        break;

    case DYNSEC_EVENT_TYPE_PTRACE:
        print_ptrace_event(fd, (struct dynsec_ptrace_umsg *)hdr);
        break;

    case DYNSEC_EVENT_TYPE_SIGNAL:
        print_signal_event(fd, (struct dynsec_signal_umsg *)hdr);
        break;

    default:
        if (hdr->report_flags & DYNSEC_REPORT_STALL) {
            respond_to_access_request(fd, hdr, response);
        }
        if (quiet)
            break;
        printf("UNKNOWN: hdr->tid:%u hdr->payload:%u hdr->req_id:%llu hdr->event_type:%u\n",
               hdr->tid, hdr->payload, hdr->req_id, hdr->event_type);
        break;
    }
}

// Event Structure
// [    dynsec_msg_hdr    ]
// [ event specific data  ]
// [ event specific blobs ]

void read_events(int fd, const char *banned_path)
{
    int timeout_ms = 100;
    char *buf = global_buf;

    memset(global_buf, 'A',  MAX_BUF_SZ);

    while (1)
    {
        struct dynsec_msg_hdr *hdr = (struct dynsec_msg_hdr *)buf;
        ssize_t bytes_read = 0;
        ssize_t bytes_parsed = 0;
        struct pollfd pollfd = {
             .fd = fd,
             .events = POLLIN | POLLOUT,
             .revents = 0,
        };
        int count = 0;
        int ret = poll(&pollfd, 1, timeout_ms);

        if (ret < 0) {
            fprintf(stderr, "poll(%m)\n");
            break;
        }
        if (ret == 0) {
            if (timeout_ms < 500)
                timeout_ms += 100;
            continue;
        }
        if (ret != 1 || !(pollfd.revents & POLLIN)) {
            fprintf(stderr, "poll ret:%d revents:%lx\n",
                    ret, pollfd.revents);
            break;
        }
        timeout_ms = 100;

        bytes_read = read(fd, buf, MAX_BUF_SZ);
        if (bytes_read <= 0) {
            if (bytes_read == -1 && errno == EAGAIN) {
                continue;
            }
            break;
        }
        if (bytes_read > largest_read) {
            largest_read = bytes_read;
        }

        while (bytes_parsed < bytes_read)
        {
            count++;
            hdr = (struct dynsec_msg_hdr *)(buf + bytes_parsed);
            histo_event_type[hdr->event_type] += 1;
            if (!(hdr->report_flags & (DYNSEC_REPORT_STALL|DYNSEC_REPORT_CACHED))) {
                total_nonstall_events += 1;
            }
            if (hdr->report_flags & DYNSEC_REPORT_STALL) {
                total_stall_events += 1;
            }
            if (hdr->report_flags & DYNSEC_REPORT_CACHED) {
                total_cached_stall_events += 1;
            }
            if (hdr->payload > max_bytes_per_event) {
                max_bytes_per_event = hdr->payload;
            }
            print_event(fd, hdr, banned_path);

            bytes_parsed += hdr->payload;
        }

        // Increment total reads
        if (count >= MAX_HISTO_SZ) {
            histo_reads[MAX_HISTO_SZ] += 1;
        } else {
            histo_reads[count] += 1;
        }
        total_reads += 1;
        total_bytes_read += bytes_read;
        total_events += count;
        if (max_parsed_per_read < count) {
            max_parsed_per_read = count;
        }
        histo_reads[count] += 1;

        // Observe bytes committed to
        memset(buf, 'A', bytes_read);
    }
}

// The reported events from these file operations
// will tell if they need a response aka are stalled.
static void *defer_rename(void *arg)
{
    int fd;
    unsigned int sleep_time = 1;

    sleep(sleep_time);
    fd = open(".rename_test1", O_CREAT);
    if (fd < 0) {
        return NULL;
    }
    close(fd);
    rename(".rename_test1", ".rename_test2");
    unlink(".rename_test1");
    unlink(".rename_test2");
    return NULL;
}


static void on_sig(int sig)
{
    int i;

    printf("\nBufferSize: %lu\n"
           "LargestRead: %u\n"
           "MaxReadHistoSize: %u\n"
           "MostEventsOnRead: %d\n"
           "LargestEventSize: %d\n"
           "TotalBytesRead: %llu\n"
           "AvgBytesPerEvent: %llu\n"
           "AvgBytesPerRead: %llu\n"
           "AvgEventsPerRead: %lf\n"
           "ReadsSaved: %llu\n"
           "TotalReads: %llu\n"
           "TotalEvents: %llu\n"
           "TotalNonStallEvents: %llu\n"
           "TotalStallEvents: %llu\n"
           "TotalCachedStallEvents: %llu\n",
           MAX_BUF_SZ,                                          // BufferSize
           largest_read,                                        // LargestRead
           MAX_HISTO_SZ,                                        // MaxReadHistoSize
           max_parsed_per_read,                                 // MostEventsOnRead
           max_bytes_per_event,                                 // LargestEventSize
           total_bytes_read,                                    // TotalBytesRead
           total_events ? total_bytes_read / total_events: 0,   // AvgBytesPerEvent
           total_reads ? total_bytes_read / total_reads: 0,     // AvgBytesPerRead
           total_events / (double)total_reads,                  // AvgEventsPerRead
           total_events - total_reads,                          // ReadsSaved
           total_reads,                                         // TotalReads
           total_events,                                        // TotalEvents
           total_nonstall_events,                               // TotalNonStallEvents
           total_stall_events,                                  // TotalStallEvents
           total_cached_stall_events                            // TotalCachedEvents
    );

    if (histo_event_type) {
        printf("---EventType Histo---\n");
        for (i = 0; i < DYNSEC_EVENT_TYPE_MAX; i++) {
            if (!histo_event_type[i]) {
                continue;
            }
            printf("Event:%d Total Events:%llu\n", i, histo_event_type[i]);
        }
    }

    if (histo_reads) {
        int min = max_parsed_per_read < MAX_HISTO_SZ ? max_parsed_per_read: MAX_HISTO_SZ;
        printf("---EventsPerRead Histo---\n");

        for (i = 0; i <= min; i++) {
            if (!histo_reads[i]) {
                continue;
            }
            printf("ReadGroup:%d Total Events:%llu\n", i, histo_reads[i]);
        }
    }
}

int main(int argc, const char *argv[])
{
    int fd;
    const char *devpath;
    unsigned long major;
    pthread_t rename_tid;
    struct sigaction action;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <desired dev filename> <major dev num>\n", argv[0]);
        return 1;
    }

    devpath = argv[1];
    major = strtoul(argv[2], NULL, 0);

    if (argc >= 4) {
        if (argv[3]) {
            quiet = (strcmp(argv[3], "-q") == 0 ||
                     strcmp(argv[3], "--quiet") == 0);
        }
    }

    fd = create_chrdev(major, 0, devpath);
    if (fd < 0) {
        return 255;
    }

    histo_reads = malloc(sizeof(*histo_reads) * MAX_HISTO_SZ);
    if (!histo_reads) {
        perror("malloc(histo_reads) ");
        return 1;
    }
    memset(histo_reads, 0, sizeof(*histo_reads) * MAX_HISTO_SZ);

    global_buf = malloc(sizeof(*global_buf) * MAX_BUF_SZ);
    if (!global_buf) {
        perror("malloc(global_buf) ");
        return 1;
    }

    histo_event_type = malloc(sizeof(*histo_event_type) *
                              DYNSEC_EVENT_TYPE_MAX);
    if (!histo_event_type) {
        perror("malloc(histo_event_type) ");
        return 1;
    }
    memset(histo_event_type, 0,
           sizeof(*histo_event_type) * DYNSEC_EVENT_TYPE_MAX);

    // Example shows we report our own rename events but not stall
    pthread_create(&rename_tid, NULL, defer_rename, NULL);
    pthread_detach(rename_tid);

    // Rough an Dirty Catch sigint
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_sig;
    sigaction(SIGINT, &action, NULL);

    // Bans filepaths containing "/foo.sh"
    read_events(fd, "/foo.sh");
    close(fd);

    return 1;
}
