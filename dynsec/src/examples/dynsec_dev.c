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
#include <pthread.h>

#include "dynsec.h"

static int quiet = 0;
static int quiet_open_events = 1;

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
        .cache_flags = 0xFFFFFFFF,
    };

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

    printf("%s: tid:%u ino:%llu dev:%#x mnt_ns:%u magic:%#lx uid:%u '%s'\n",
        ev_str, exec_msg->msg.task.tid, exec_msg->msg.file.ino, exec_msg->msg.file.dev,
        exec_msg->msg.task.mnt_ns, exec_msg->msg.file.sb_magic, exec_msg->msg.task.uid, path
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
        printf(" chmod umode[%#04x -> %#04x", setattr->msg.file.umode,
               setattr->msg.attr_umode);
    }
    if (setattr->msg.attr_mask & DYNSEC_SETATTR_UID) {
        printf(" chown uid[%u -> %u", setattr->msg.file.uid,
               setattr->msg.attr_uid);
    }
    if (setattr->msg.attr_mask & DYNSEC_SETATTR_GID) {
        printf(" chown gid[%u -> %u", setattr->msg.file.gid,
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

    case DYNSEC_EVENT_TYPE_LINK:
        print_link_event(fd, (struct dynsec_link_umsg *)hdr);
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
    char buf[8192 * 2];
    struct dynsec_exec_umsg *exec_msg;

    memset(buf, 'A', sizeof(buf));

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
        int ret = poll(&pollfd, 1, -1);

        if (ret < 0) {
            fprintf(stderr, "poll(%m)\n");
            break;
        }
        if (ret != 1 || !(pollfd.revents & POLLIN)) {
            fprintf(stderr, "poll ret:%d revents:%lx\n",
                    ret, pollfd.revents);
            break;
        }

        bytes_read = read(fd, buf, sizeof(buf));
        if (bytes_read <= 0) {
            break;
        }

        while (bytes_parsed < bytes_read)
        {
            count++;
            hdr = (struct dynsec_msg_hdr *)(buf + bytes_parsed);
            print_event(fd, hdr, banned_path);

            bytes_parsed += hdr->payload;
        }
        if (!quiet && count > 1) {
            printf("multiread count: %d\n", count);
        }

        // Observe bytes committed to
        memset(buf, 'A', sizeof(buf));
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

int main(int argc, const char *argv[])
{
    int fd;
    const char *devpath;
    unsigned long major;
    pthread_t rename_tid;

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

    // Example shows we report our own rename events but not stall
    pthread_create(&rename_tid, NULL, defer_rename, NULL);
    pthread_detach(rename_tid);

    // Bans filepaths containing "/foo.sh"
    read_events(fd, "/foo.sh");
    close(fd);

    return 1;
}
