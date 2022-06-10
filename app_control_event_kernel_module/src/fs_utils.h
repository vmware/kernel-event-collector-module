/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright 2022 VMware, Inc. All rights reserved.

#pragma once

#include <linux/fs.h>
#include <linux/magic.h>
#include "config.h"

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

// enums based on MAGIC definitions of file system types
// from linux/magic.h kernel version 5.18
enum file_system_magic_bits_e {

     ADFS_SUPER_MAGIC_BIT, // 0	
     AFFS_SUPER_MAGIC_BIT,
     AFS_SUPER_MAGIC_BIT,  
     AUTOFS_SUPER_MAGIC_BIT,
     CEPH_SUPER_MAGIC_BIT,
     CODA_SUPER_MAGIC_BIT,	
     CRAMFS_MAGIC_BIT,	
     CRAMFS_MAGIC_BIT_WEND,
     DEBUGFS_MAGIC_BIT,          
     SECURITYFS_MAGIC_BIT,	
     SELINUX_MAGIC_BIT,  // 10		
     SMACK_MAGIC_BIT,		
     RAMFS_MAGIC_BIT,	
     TMPFS_MAGIC_BIT,		
     HUGETLBFS_MAGIC_BIT,
     SQUASHFS_MAGIC_BIT,
     ECRYPTFS_SUPER_MAGIC_BIT,	
     EFS_SUPER_MAGIC_BIT,
     EROFS_SUPER_MAGIC_BIT_V1,	
     EXT2_SUPER_MAGIC_BIT,	
     EXT3_SUPER_MAGIC_BIT,   // 20	
     XENFS_SUPER_MAGIC_BIT,	
     EXT4_SUPER_MAGIC_BIT,	
     BTRFS_SUPER_MAGIC_BIT,	
     NILFS_SUPER_MAGIC_BIT,	
     F2FS_SUPER_MAGIC_BIT,	
     HPFS_SUPER_MAGIC_BIT,	
     ISOFS_SUPER_MAGIC_BIT,	
     JFFS2_SUPER_MAGIC_BIT,	
     XFS_SUPER_MAGIC_BIT,	
     PSTOREFS_MAGIC_BIT,     // 30	
     EFIVARFS_MAGIC_BIT,		
     HOSTFS_SUPER_MAGIC_BIT,	
     OVERLAYFS_SUPER_MAGIC_BIT,	
     FUSE_SUPER_MAGIC_BIT,	
     MINIX_SUPER_MAGIC_BIT,
     MINIX_SUPER_MAGIC_BIT2,
     MINIX2_SUPER_MAGIC_BIT,
     MINIX2_SUPER_MAGIC_BIT2,
     MINIX3_SUPER_MAGIC_BIT,
     MSDOS_SUPER_MAGIC_BIT,  // 40	
     EXFAT_SUPER_MAGIC_BIT,	
     NCP_SUPER_MAGIC_BIT,
     NFS_SUPER_MAGIC_BIT,	
     OCFS2_SUPER_MAGIC_BIT,	
     OPENPROM_SUPER_MAGIC_BIT,	
     QNX4_SUPER_MAGIC_BIT,
     QNX6_SUPER_MAGIC_BIT,
     AFS_FS_MAGIC_BIT,		
     REISERFS_SUPER_MAGIC_BIT,	
     SMB_SUPER_MAGIC_BIT,    // 50
     CIFS_SUPER_MAGIC_BIT,
     SMB2_SUPER_MAGIC_BIT,	
     CGROUP_SUPER_MAGIC_BIT,	
     CGROUP2_SUPER_MAGIC_BIT,	
     RDTGROUP_SUPER_MAGIC_BIT,	
     STACK_END_MAGIC_BIT,	
     TRACEFS_MAGIC_BIT,       
     V9FS_MAGIC_BIT,		
     BDEVFS_MAGIC_BIT,           
     DAXFS_MAGIC_BIT,       // 60     
     BINFMTFS_MAGIC_BIT,         
     DEVPTS_SUPER_MAGIC_BIT,	
     BINDERFS_SUPER_MAGIC_BIT,	
     FUTEXFS_SUPER_MAGIC_BIT,	
     PIPEFS_MAGIC_BIT,           
     PROC_SUPER_MAGIC_BIT,	
     SOCKFS_MAGIC_BIT,		
     SYSFS_MAGIC_BIT,		
     USBDEVICE_SUPER_MAGIC_BIT,	
     MTD_INODE_FS_MAGIC_BIT,     //  70
     ANON_INODE_FS_MAGIC_BIT,	
     BTRFS_TEST_MAGIC_BIT,	
     NSFS_MAGIC_BIT,		
     BPF_FS_MAGIC_BIT,		
     AAFS_MAGIC_BIT,		
     ZONEFS_MAGIC_BIT,		
     UDF_SUPER_MAGIC_BIT,	
     BALLOON_KVM_MAGIC_BIT,	
     ZSMALLOC_MAGIC_BIT,		
     DMA_BUF_MAGIC_BIT,		// 80
     DEVMEM_MAGIC_BIT,		
     Z3FOLD_MAGIC_BIT,		
     PPC_CMM_MAGIC_BIT,		
     SECRETMEM_MAGIC_BIT,	

};

// check if client is concerned about this file system type
static inline bool __is_client_concerned_filesystem(const struct super_block *sb)
{
#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC 0x58465342
#endif

#ifndef SMB2_SUPER_MAGIC
#define SMB2_SUPER_MAGIC 0xFE534D42
#endif

    uint64_t result = 0;

    switch (sb->s_magic) {
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
