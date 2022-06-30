/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2022 VMware, Inc. All rights reserved.

#pragma once

#ifdef CONFIG_SECURITY_PATH
#include <linux/version.h>

extern int dynsec_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode,
                      unsigned int dev);

extern int dynsec_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode);

extern int dynsec_path_rmdir(const struct path *dir, struct dentry *dentry);

extern int dynsec_path_unlink(const struct path *dir, struct dentry *dentry);

extern int dynsec_path_symlink(const struct path *dir, struct dentry *dentry,
                        const char *old_name);

extern int dynsec_path_link(struct dentry *old_dentry, const struct path *new_dir,
                     struct dentry *new_dentry);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
extern int dynsec_path_rename(const struct path *old_dir, struct dentry *old_dentry,
                       const struct path *new_dir, struct dentry *new_dentry);
#else
extern int dynsec_path_rename(const struct path *old_dir, struct dentry *old_dentry,
                       const struct path *new_dir, struct dentry *new_dentry,
                       unsigned int flags);
#endif

extern int dynsec_path_truncate(const struct path *path);

extern int dynsec_path_chmod(const struct path *path, umode_t mode);

extern int dynsec_path_chown(const struct path *path, kuid_t uid, kgid_t gid);

#endif /* CONFIG_SECURITY_PATH */
