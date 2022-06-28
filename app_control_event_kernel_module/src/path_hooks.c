// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

// File is intented to support kernels with CONFIG_SECURITY_PATH enabled

#ifdef CONFIG_SECURITY_PATH
#include <linux/version.h>
#include <linux/uidgid.h>
#include <linux/fs.h>
#include <linux/path.h>

int dynsec_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode,
                      unsigned int dev)
{
    return 0;
}

int dynsec_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode)
{
    return 0;
}

int dynsec_path_rmdir(const struct path *dir, struct dentry *dentry)
{
    return 0;
}

int dynsec_path_unlink(const struct path *dir, struct dentry *dentry)
{
    return 0;
}

int dynsec_path_symlink(const struct path *dir, struct dentry *dentry,
                        const char *old_name)
{
    return 0;
}

int dynsec_path_link(struct dentry *old_dentry, const struct path *new_dir,
                     struct dentry *new_dentry)
{
    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
int dynsec_path_rename(const struct path *old_dir, struct dentry *old_dentry,
                       const struct path *new_dir, struct dentry *new_dentry)
#else
int dynsec_path_rename(const struct path *old_dir, struct dentry *old_dentry,
                       const struct path *new_dir, struct dentry *new_dentry,
                       unsigned int flags)
#endif
{
    return 0;
}

int dynsec_path_truncate(const struct path *path)
{
    return 0;
}

int dynsec_path_chmod(const struct path *path, umode_t mode)
{
    return 0;
}

int dynsec_path_chown(const struct path *path, kuid_t uid, kgid_t gid)
{
    return 0;
}

#endif /* CONFIG_SECURITY_PATH */
