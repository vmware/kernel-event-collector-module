/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright 2022 VMware, Inc. All rights reserved.

#pragma once

#include <linux/fs.h>
#include <linux/magic.h>

static inline const struct inode * __file_inode(const struct file *file)
{
    if (file && file->f_path.dentry) {
        return file->f_path.dentry->d_inode;
    }
    return NULL;
}

static inline bool __is_special_filesystem(const struct super_block *sb)
{
#ifndef TRACEFS_MAGIC
#define TRACEFS_MAGIC          0x74726163
#endif

    switch (sb->s_magic) {
    // Special Kernel File Systems
    case CGROUP_SUPER_MAGIC:
#ifdef CGROUP2_SUPER_MAGIC
    case CGROUP2_SUPER_MAGIC:
#endif /* CGROUP2_SUPER_MAGIC */
    case SELINUX_MAGIC:
#ifdef SMACK_MAGIC
    case SMACK_MAGIC:
#endif /* SMACK_MAGIC */
    case SYSFS_MAGIC:
    case PROC_SUPER_MAGIC:
    case SOCKFS_MAGIC:
    case DEVPTS_SUPER_MAGIC:
    case FUTEXFS_SUPER_MAGIC:
    case ANON_INODE_FS_MAGIC:
    case DEBUGFS_MAGIC:
    case TRACEFS_MAGIC:
#ifdef BINDERFS_SUPER_MAGIC
    case BINDERFS_SUPER_MAGIC:
#endif /* BINDERFS_SUPER_MAGIC */
#ifdef BPF_FS_MAGIC
    case BPF_FS_MAGIC:
#endif /* BPF_FS_MAGIC */
#ifdef PIPEFS_MAGIC
    case PIPEFS_MAGIC:
#endif

        return true;

    default:
        return false;
    }

    return false;
}

static inline bool __is_procfs(const struct super_block *sb)
{
    return (sb->s_magic == PROC_SUPER_MAGIC);
}

static inline bool __is_fusefs(const struct super_block *sb)
{
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif
    return (sb->s_magic == FUSE_SUPER_MAGIC);
}
static inline bool __is_overlayfs(const struct super_block *sb)
{
#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC   0x794c7630
#endif
    return (sb->s_magic == OVERLAYFS_SUPER_MAGIC);
}

static inline bool __is_stacked_filesystem(const struct super_block *sb)
{
#ifndef GFS2_MAGIC
#define GFS2_MAGIC      0x01161970
#endif

#ifndef CEPH_SUPER_MAGIC
#define CEPH_SUPER_MAGIC 0x00c36400
#endif

#ifndef CIFS_MAGIC_NUMBER
#define CIFS_MAGIC_NUMBER 0xFF534D42
#endif

    switch (sb->s_magic) {
    case FUSE_SUPER_MAGIC:
    case ECRYPTFS_SUPER_MAGIC:
    case OVERLAYFS_SUPER_MAGIC:

    case NFS_SUPER_MAGIC:
    case GFS2_MAGIC:
    case CEPH_SUPER_MAGIC:
    case SMB_SUPER_MAGIC:
    case CIFS_MAGIC_NUMBER:
        return true;

    default:
        return false;
    }
    return false;
}
