// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

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

#include "dynsec.h"

static int quiet = 0;

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

int respond_to_access_request(int fd, uint64_t req_id,
                              uint32_t event_type, uint32_t pid, int response_type)
{
    ssize_t ret;
    struct dynsec_response response = {
        .req_id = req_id,
        .event_type = event_type,
        .pid = pid,
        .response = response_type,
        .cache_flags = 0xFFFFFFFF,
    };

    ret = write(fd, &response, sizeof(response));
    if (ret < 0) {
        return -errno;
    }
    return 0;
}

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
        int response = DYNSEC_RESPONSE_ALLOW;

        if (ret <= 0) {
            continue;
        }

        bytes_read = read(fd, buf, sizeof(buf));
        if (bytes_read <= 0) {
            if (bytes_read == 0 || errno != -EAGAIN) {
                break;
            }
        }

        if (hdr->event_type == DYNSEC_EVENT_TYPE_EXEC) {
            char *path = "";
            struct dynsec_exec_umsg *exec_msg = (struct dynsec_exec_umsg *)hdr;

            if (hdr->payload != exec_msg->hdr.payload ||
                hdr->req_id != exec_msg->hdr.req_id || 
                hdr->event_type != exec_msg->hdr.event_type) {
                printf("hdr->payload:%u hdr->req_id:%llu hdr->event_type:%#x\n",
                       hdr->payload, hdr->req_id, hdr->event_type);
                printf("payload:%u req_id:%llu event_type:%#x\n", exec_msg->hdr.payload,
                       exec_msg->hdr.req_id, exec_msg->hdr.event_type);
            } else {
                if (exec_msg->msg.path_offset) {
                    path = buf + exec_msg->msg.path_offset;
                    // if (path) {
                    //     printf("offset:%u size:%u strlen:%lu path:%s\n",
                    //            exec_msg->msg.path_offset, exec_msg->msg.path_size,
                    //            strlen(path), path);
                    // }
                }

                // TODO: print/log after any event requiring a response
                // Ban some matching substring
                if (banned_path && *banned_path && path && *path &&
                    strstr(path, banned_path)) {
                    response = DYNSEC_RESPONSE_EPERM;
                }
                if (quiet) goto dispatch;

                printf("EXEC: tid:%u ino:%llu dev:%#x magic:%#lx uid:%u '%s'\n",
                       exec_msg->msg.pid, exec_msg->msg.ino, exec_msg->msg.dev,
                       exec_msg->msg.sb_magic, exec_msg->msg.uid, path
                );
            }
        } else if (hdr->event_type == DYNSEC_EVENT_TYPE_UNLINK ||
                   hdr->event_type == DYNSEC_EVENT_TYPE_RMDIR) {
            char *path = "";

            struct dynsec_unlink_umsg *unlink_msg = (struct dynsec_unlink_umsg *)hdr;

            if (hdr->payload != unlink_msg->hdr.payload ||
                hdr->req_id != unlink_msg->hdr.req_id || 
                hdr->event_type != unlink_msg->hdr.event_type) {
                printf("hdr->payload:%u hdr->req_id:%llu hdr->event_type:%#x\n",
                       hdr->payload, hdr->req_id, hdr->event_type);
                printf("payload:%u req_id:%llu event_type:%#x\n", unlink_msg->hdr.payload,
                       unlink_msg->hdr.req_id, unlink_msg->hdr.event_type);
            } else {
                if (quiet) goto dispatch;
                if (unlink_msg->msg.path_offset) {
                    path = buf + unlink_msg->msg.path_offset;
                }
                printf("UNLINK: tid:%u ino:%llu dev:%#x umode:%#04x magic:%#lx uid:%u "
                       "parent[%llu:%#x] '%s'\n",
                       unlink_msg->hdr.pid, unlink_msg->msg.ino, unlink_msg->msg.dev,
                       unlink_msg->msg.mode, unlink_msg->msg.sb_magic,
                       unlink_msg->msg.uid, unlink_msg->msg.parent_ino,
                       unlink_msg->msg.parent_dev, path
                );
            }
        } else if (hdr->event_type == DYNSEC_EVENT_TYPE_RENAME) {
            char *old_path = "";
            char *new_path = "";

            struct dynsec_rename_umsg *rename_msg = (struct dynsec_rename_umsg *)hdr;

            if (hdr->payload != rename_msg->hdr.payload ||
                hdr->req_id != rename_msg->hdr.req_id || 
                hdr->event_type != rename_msg->hdr.event_type) {
                printf("hdr->payload:%u hdr->req_id:%llu hdr->event_type:%#x\n",
                       hdr->payload, hdr->req_id, hdr->event_type);
                printf("payload:%u req_id:%llu event_type:%#x\n", rename_msg->hdr.payload,
                       rename_msg->hdr.req_id, rename_msg->hdr.event_type);
            } else {
                if (quiet) goto dispatch;
                if (rename_msg->msg.old_path_offset) {
                    old_path = buf + rename_msg->msg.old_path_offset;
                }
                if (rename_msg->msg.new_path_offset) {
                    new_path = buf + rename_msg->msg.new_path_offset;
                }

                printf("RENAME: tid:%u dev:%#x magic:%#lx uid:%u "
                       "'%s'[%llu %#04x %llu]->'%s'[%llu %#04x %llu]\n",
                       rename_msg->hdr.pid, rename_msg->msg.dev,
                       rename_msg->msg.sb_magic,
                       rename_msg->msg.uid,
                       old_path, rename_msg->msg.old_ino, rename_msg->msg.old_mode,
                       rename_msg->msg.old_parent_ino,

                       new_path, rename_msg->msg.new_ino, rename_msg->msg.new_mode,
                       rename_msg->msg.new_parent_ino
                );
            }
        }
        else {
            if (quiet) goto dispatch;
            printf("hdr->payload:%u hdr->req_id:%llu hdr->event_type:%#x\n",
                   hdr->payload, hdr->req_id, hdr->event_type);
        }

dispatch:
        ret = respond_to_access_request(fd, hdr->req_id, hdr->event_type, hdr->pid, response);
        if (ret < 0) {
            fprintf(stderr, "Unable to response to:%llu %#x resp:%d err:%d\n",
                    hdr->req_id, hdr->event_type, response, ret);
        }

        // Observe bytes committed to
        memset(buf, 'A', sizeof(buf));
    }
}


int main(int argc, const char *argv[])
{
    int fd;
    const char *devpath;
    unsigned long major;

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

    // Bans filepaths containing "/foo.sh"
    read_events(fd, "/foo.sh");
    close(fd);

    return 1;
}
