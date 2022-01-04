/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright 2021 VMware Inc.  All rights reserved. */

#pragma once

#include "process-context.h"
#include "path-cache.h"

#define SANE_PATH(PATH) PATH ? PATH : "<unknown>"

bool ec_file_helper_init(ProcessContext *context);
bool ec_file_get_path(struct file const *file, char *buffer, unsigned int buflen, char **pathname);
bool ec_path_get_path(struct path const *path, char *buffer, unsigned int buflen, char **pathname);
bool ec_dentry_get_path(struct dentry const *dentry, char *buffer, unsigned int buflen, char **pathname);
char *ec_dentry_to_path(struct dentry const *dentry, char *buf, int buflen);
char *ec_lsm_dentry_path(struct dentry const *dentry, char *path, int len);
struct inode const *ec_get_inode_from_file(struct file const *file);
void ec_get_devinfo_from_file(struct file const *file, uint64_t *device, uint64_t *inode);
void ec_get_devinfo_fs_magic_from_file(struct file const *file, uint64_t *device, uint64_t *inode, uint64_t *fs_magic);
void ec_get_devinfo_from_path(struct path const *path, uint64_t *device, uint64_t *inode, uint64_t *fs_magic);
struct inode const *ec_get_inode_from_dentry(struct dentry const *dentry);
umode_t ec_get_mode_from_file(struct file const *file);
struct super_block const *ec_get_sb_from_file(struct file const *file);
bool ec_is_interesting_file(struct file *file);
int ec_is_special_file(char *pathname, int len);
bool ec_may_skip_unsafe_vfs_calls(struct file const *file);
bool ec_file_exists(int dfd, const char __user *filename);

struct path_lookup
{
    struct file const  *file;
    struct path const  *path;
    const char __user  *filename;
    char               *path_buffer;
    bool                ignore_spcial;
};

PathData *ec_file_get_path_data(
    struct path_lookup *path_lookup,
    ProcessContext     *context);
void ec_file_helper_send_path_event(
    PathData         *path_data,
    ProcessContext   *context);
