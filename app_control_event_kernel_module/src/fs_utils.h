/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright 2022 VMware, Inc. All rights reserved.

#pragma once

#include <linux/fs.h>
#include <linux/magic.h>
#include "config.h"
#include "dynsec.h"

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

// check if client is concerned about this file system type
static inline bool __is_client_concerned_filesystem_by_magic(const unsigned long magic)
{
#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif

#ifndef SMB2_SUPER_MAGIC
#define SMB2_SUPER_MAGIC 0xFE534D42
#endif

    uint64_t result = 0;

    // If none are set, don't filter by file system type
    if (!global_config.file_system_stall_mask) {
        return true;
    }

    switch (magic) {
    case EXT2_SUPER_MAGIC:  // EXT3 and EXT4 are the same magic
        result = get_file_system_stall_bit(EXT2_SUPER_MAGIC_BIT);
        break;

    case XFS_SUPER_MAGIC:
        result = get_file_system_stall_bit(XFS_SUPER_MAGIC_BIT);
        break;

    case CIFS_MAGIC_NUMBER:
        result = get_file_system_stall_bit(CIFS_SUPER_MAGIC_BIT);
        break;

    case ISOFS_SUPER_MAGIC:
        result = get_file_system_stall_bit(ISOFS_SUPER_MAGIC_BIT);
        break;

    case SMB_SUPER_MAGIC:
        result = get_file_system_stall_bit(SMB_SUPER_MAGIC_BIT);
        break;

    case SMB2_SUPER_MAGIC:
        result = get_file_system_stall_bit(SMB2_SUPER_MAGIC_BIT);
        break;

    case REISERFS_SUPER_MAGIC:
        result = get_file_system_stall_bit(REISERFS_SUPER_MAGIC_BIT);
        break;

    case USBDEVICE_SUPER_MAGIC:
        result = get_file_system_stall_bit(USBDEVICE_SUPER_MAGIC_BIT);
        break;

    case NFS_SUPER_MAGIC:
        result = get_file_system_stall_bit(NFS_SUPER_MAGIC_BIT);
        break;

    case MSDOS_SUPER_MAGIC:
        result = get_file_system_stall_bit(MSDOS_SUPER_MAGIC_BIT);
        break;

    case HPFS_SUPER_MAGIC:
        result = get_file_system_stall_bit(HPFS_SUPER_MAGIC_BIT);
        break;

    case JFFS2_SUPER_MAGIC:
        result = get_file_system_stall_bit(JFFS2_SUPER_MAGIC_BIT);
        break;

    case BTRFS_SUPER_MAGIC:
        result = get_file_system_stall_bit(BTRFS_SUPER_MAGIC_BIT);
        break;

    case FUSE_SUPER_MAGIC:
        result = get_file_system_stall_bit(FUSE_SUPER_MAGIC_BIT);
        break;
    }
    if (result) return true;

    return false;
}

// check if client is concerned about this file system type
static inline bool __is_client_concerned_filesystem(const struct super_block *sb)
{
    if (!sb) {
        if (stall_mode_enabled())
            return true;
        else
            return false;
    }
    return __is_client_concerned_filesystem_by_magic(sb->s_magic);
}
