/*
 * Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "file_notify_transport.h"
#include "file_notify.skel.h"

static const struct inode_cache_entry empty_inode_obj;

static int debug = 1;


int file_notify__bpf_lsm_enabled(void)
{
    ssize_t bytes_read;
    char buf[256] = {};
    int fd = openat(AT_FDCWD, "/sys/kernel/security/lsm", O_RDONLY);
    int ret = -ENOENT;

    if (fd < 0)
    {
        return -errno;
    }

    bytes_read = read(fd, buf, sizeof(buf));
    if (bytes_read < 0)
    {
        ret = -errno;
    }
    close(fd);
    fd = -1;

    // // Not worth tokenizing yet, but we could strsep(',')
    if (strcmp(buf, "bpf") == 0 ||      // Only LSM prog loaded... "WHAT???!!!!"
        strstr(buf, ",bpf,") != NULL || // Someone loaded the LSMs in a customized way
        strstr(buf, "bpf,") != NULL ||  // TODO: modify to do "startswith"
        strstr(buf, ",bpf") != NULL)    // TODO: modify to do "endswith" (the likeliest case)
    {
        ret = 0;
    }

    return ret;
}


static int insert_inode_obj(int map_fd, int inode_fd,
                            const struct inode_cache_entry *obj)
{
    int ret = -EINVAL;

    if (map_fd >= 0 && inode_fd >= 0) {
        ret = bpf_map_update_elem(map_fd, &inode_fd, obj, BPF_NOEXIST);

        if (ret < 0) {
            ret = -errno;

            if (debug)
                fprintf(stderr, "bpf_map_update_elem(%d, %d) %m\n", map_fd, inode_fd);
        }
    }

    return ret;
}


static int __file_notify__mark_inode(int map_fd, int inode_fd, uint16_t flags)
{
    struct inode_cache_entry obj = empty_inode_obj;

    obj.type_flags |= flags;

    return insert_inode_obj(map_fd, inode_fd, &obj);
}



int file_notify__ban_fd(const struct file_notify_bpf *skel, int fd)
{
    int ret = -EINVAL;
    int map_fd = -1;

    if (fd < 0)
    {
        goto out;
    }

    if (!skel)
    {
        goto out;
    }
    map_fd = bpf_map__fd(skel->maps.inode_storage_map);
    if (map_fd < 0)
    {
        goto out;
    }

    ret = __file_notify__mark_inode(map_fd, fd, INODE_TYPE_LABEL_BANNED);

out:
    return ret;
}

int file_notify__ban_dfd_filepath(const struct file_notify_bpf *skel,
                                  int dfd, const char *filepath)
{
    int ret = -EINVAL;
    int fd = -1;
    int map_fd = -1;

    if (!skel)
    {
        goto out;
    }
    map_fd = bpf_map__fd(skel->maps.inode_storage_map);
    if (map_fd < 0)
    {
        goto out;
    }

    fd = openat(dfd, filepath, O_PATH);
    if (fd < 0)
    {
        ret = -errno;
        goto out;
    }

    ret = __file_notify__mark_inode(map_fd, fd, INODE_TYPE_LABEL_BANNED);

out:
    if (fd >= 0)
    {
        close(fd);
        fd = -1;
    }

    return ret;
}

int file_notify__ban_filepath(const struct file_notify_bpf *skel,
                              const char *filepath)
{
    return file_notify__ban_dfd_filepath(skel, AT_FDCWD, filepath);
}


