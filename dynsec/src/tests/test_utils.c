// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include "dynsec.h"

#include "test_utils.h"
#include "client.h"
#include "print.h"


static void stat_to_dynsec_file(const struct stat *sb,
                         struct dynsec_file *file, uint32_t attr_mask)
{
    if (!sb || !attr_mask || !file) {
        return;
    }

    memset(file, 0, sizeof(*file));

    if (attr_mask & DYNSEC_FILE_ATTR_INODE) {
        file->ino = sb->st_ino;
        file->umode = sb->st_mode;
        file->uid = sb->st_uid;
        file->gid = sb->st_gid;
        file->size = sb->st_size;
        file->nlink = sb->st_nlink;
        file->attr_mask |= DYNSEC_FILE_ATTR_INODE;
    }
    if (attr_mask & DYNSEC_FILE_ATTR_DEVICE) {
        file->dev = sb->st_dev;
        file->attr_mask |= DYNSEC_FILE_ATTR_DEVICE;
    }

    if (attr_mask & DYNSEC_FILE_ATTR_PARENT_INODE) {
        file->parent_ino = sb->st_ino;
        file->parent_umode = sb->st_mode;
        file->parent_uid = sb->st_uid;
        file->parent_gid = sb->st_gid;
        file->attr_mask |= DYNSEC_FILE_ATTR_PARENT_INODE;
    }
    if (attr_mask & DYNSEC_FILE_ATTR_PARENT_DEVICE) {
        file->parent_dev = sb->st_dev;
        file->attr_mask |= DYNSEC_FILE_ATTR_PARENT_DEVICE;
    }
}

static void statfs_to_dynsec_file(const struct statfs *fsb,
                           struct dynsec_file *file, uint32_t attr_mask)
{
    if (!fsb || !attr_mask || !file) {
        return;
    }

    if (attr_mask & DYNSEC_FILE_ATTR_DEVICE) {
        file->sb_magic = fsb->f_type;
        file->attr_mask |= DYNSEC_FILE_ATTR_DEVICE;
    }
}

void fill_in_exp_dynsec_file(int parent_fd,
                             int fd, struct dynsec_file *file)
{
    struct stat sb;
    struct stat sb_parent;
    struct statfs fsb;
    int ret;

    if (parent_fd < 0 || fd < 0 || !file) {
        return;
    }

    ret = fstat(fd, &sb);
    if (!ret) {
        stat_to_dynsec_file(&sb, file,
                            DYNSEC_FILE_ATTR_INODE|
                            DYNSEC_FILE_ATTR_DEVICE);
    }
    ret = fstat(parent_fd,  &sb_parent);
    if (!ret) {
        stat_to_dynsec_file(&sb_parent, file,
                            DYNSEC_FILE_ATTR_PARENT_INODE|
                            DYNSEC_FILE_ATTR_PARENT_DEVICE);
    }

    ret = fstatfs(fd, &fsb);
    if (!ret) {
        statfs_to_dynsec_file(&fsb, file,
                              DYNSEC_FILE_ATTR_DEVICE);
    }
}

void setup_base_test_data(struct test_case *test_case,
                          const char *basedir)
{
    struct base_test_data *base = NULL;
    if (!test_case || !basedir || !*basedir) {
        return;
    }

    base = &test_case->base;
    memset(base, 0, sizeof(*base));
    base->dirfd = -1;
    base->dir = basedir;
    base->pipe[0] = -1;
    base->pipe[1] = -1;
    pipe(base->pipe);

    base->dirfd = open(base->dir, O_DIRECTORY);
}

void teardown_base_test_data(struct test_case *test_case)
{
    struct base_test_data *base = NULL;
    if (!test_case) {
        return;
    }

    base = &test_case->base;
    if (base->dirfd >= 0) {
        close(base->dirfd);
        base->dirfd = -1;
    }
    if (base->pipe[0] >= 0) {
        close(base->pipe[0]);
        base->pipe[0] = -1;
    }
    if (base->pipe[1] >= 0) {
        close(base->pipe[1]);
        base->pipe[1] = -1;
    }
}

void write_test_result(struct test_case *test_case,
                      int result, int act_errno,
                      const char *msg)
{
    struct base_test_data *base = NULL;
    if (!test_case) {
        return;
    }

    base = &test_case->base;
    if (base->pipe[1] < 0) {
        return;
    }

    base->result.result = result;
    base->result.act_errno = act_errno;
    if (msg && *msg) {
        strncpy(base->result.msg, msg,
                sizeof(base->result.msg) -1);
    } else {
        memset(base->result.msg, 0, sizeof(base->result.msg));
    }
    if (base->pipe[0] >= 0) {
        close(base->pipe[0]);
        base->pipe[0] = -1;
    }
    write(base->pipe[1], &base->result, sizeof(base->result));
    close(base->pipe[1]);
    base->pipe[1] = -1;
}

void read_test_result(struct test_case *test_case)
{
    struct base_test_data *base = NULL;
    if (!test_case) {
        return;
    }

    base = &test_case->base;
    if (base->pipe[0] < 0) {
        return;
    }
    if (base->pipe[1] >= 0) {
        close(base->pipe[1]);
        base->pipe[1] = -1;
    }
    read(base->pipe[0], &base->result, sizeof(base->result));
    close(base->pipe[0]);
    base->pipe[0] = -1;
}

