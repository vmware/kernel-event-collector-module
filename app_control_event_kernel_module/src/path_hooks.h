/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c); 2021 VMware, Inc. All rights reserved.

#pragma once

#ifdef CONFIG_SECURITY_PATH

int dynsec_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode,
                      unsigned int dev);

int dynsec_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode);

int dynsec_path_rmdir(const struct path *dir, struct dentry *dentry);

int dynsec_path_unlink(const struct path *dir, struct dentry *dentry);

int dynsec_path_symlink(const struct path *dir, struct dentry *dentry,
                        const char *old_name);

int dynsec_path_link(struct dentry *old_dentry, const struct path *new_dir,
                     struct dentry *new_dentry);

int dynsec_path_rename(const struct path *old_dir, struct dentry *old_dentry,
                       const struct path *new_dir, struct dentry *new_dentry,
                       unsigned int flags);

int dynsec_path_truncate(const struct path *path);

int dynsec_path_chmod(const struct path *path, umode_t mode);

int dynsec_path_chown(const struct path *path, kuid_t uid, kgid_t gid);

#endif /* CONFIG_SECURITY_PATH */
