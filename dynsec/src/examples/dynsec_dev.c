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

    if (exec_msg->msg.path_offset) {
        path = start + exec_msg->msg.path_offset;
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
        ev_str, exec_msg->msg.task.tid, exec_msg->msg.ino, exec_msg->msg.dev,
        exec_msg->msg.task.mnt_ns, exec_msg->msg.sb_magic, exec_msg->msg.task.uid, path
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

    if (unlink_msg->msg.path_offset) {
        path = start + unlink_msg->msg.path_offset;
    }

    if (unlink_msg->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &unlink_msg->hdr, response);

    if (quiet) return;

    printf("%s: tid:%u ino:%llu dev:%#x mnt_ns:%u umode:%#04x magic:%#lx uid:%u "
        "parent_ino:%llu '%s'\n", ev_str,
        unlink_msg->hdr.tid, unlink_msg->msg.ino, unlink_msg->msg.dev,
        unlink_msg->msg.task.mnt_ns, unlink_msg->msg.mode, unlink_msg->msg.sb_magic,
        unlink_msg->msg.task.uid, unlink_msg->msg.parent_ino, path);
}

void print_rename_event(int fd, struct dynsec_rename_umsg *rename_msg)
{
    int response = DYNSEC_RESPONSE_ALLOW;
    const char *old_path = "";
    const char *new_path = "";
    const char *start = (const char *)rename_msg;

    if (rename_msg->msg.old_path_offset) {
        old_path = start + rename_msg->msg.old_path_offset;
    }
    if (rename_msg->msg.new_path_offset) {
        new_path = start + rename_msg->msg.new_path_offset;
    }

    if (rename_msg->hdr.report_flags & DYNSEC_REPORT_STALL)
        respond_to_access_request(fd, &rename_msg->hdr, response);

    if (quiet) return;

    printf("RENAME: tid:%u dev:%#x mnt_ns:%u magic:%#lx uid:%u "
        "'%s'[%llu %#04x %llu]->'%s'[%llu %#04x %llu]\n",
        rename_msg->hdr.tid, rename_msg->msg.dev, rename_msg->msg.task.mnt_ns,
        rename_msg->msg.sb_magic,
        rename_msg->msg.task.uid,
        old_path, rename_msg->msg.old_ino, rename_msg->msg.old_mode,
        rename_msg->msg.old_parent_ino,

        new_path, rename_msg->msg.new_ino, rename_msg->msg.new_mode,
        rename_msg->msg.new_parent_ino
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
    char buf[8192];
    struct dynsec_exec_umsg *exec_msg;

    memset(buf, 'A', sizeof(buf));

    while (1)
    {
        struct dynsec_msg_hdr *hdr = (struct dynsec_msg_hdr *)buf;
        ssize_t bytes_read = 0;
        struct pollfd pollfd = {
             .fd = fd,
             .events = POLLIN | POLLOUT,
             .revents = 0,
        };
        int ret = poll(&pollfd, 1, -1);

        bytes_read = read(fd, buf, sizeof(buf));
        if (bytes_read <= 0) {
            // TODO: handle non-blocking more safely
            break;
        }

        print_event(fd, hdr, banned_path);

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
