/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

// ioctls
#define DYNSEC_CMD_DISABLE       0x00000001
#define DYNSEC_CMD_BYPASS        0x00000002
// objects or contexts we want to always allow
#define DYNSEC_CMD_EXCEPTION     0x00000004

#define DYNSEC_EVENT_TYPE_EXEC      0x00000001
#define DYNSEC_EVENT_TYPE_RENAME    0x00000002
#define DYNSEC_EVENT_TYPE_UNLINK    0x00000004
#define DYNSEC_EVENT_TYPE_RMDIR     0x00000008

// Well see how long this can map 1:1
#define DYNSEC_LSM_bprm_set_creds       DYNSEC_EVENT_TYPE_EXEC
#define DYNSEC_LSM_inode_rename         DYNSEC_EVENT_TYPE_RENAME
#define DYNSEC_LSM_inode_unlink         DYNSEC_EVENT_TYPE_UNLINK
#define DYNSEC_LSM_inode_rmdir          DYNSEC_EVENT_TYPE_RMDIR

#define DYNSEC_RESPONSE_ALLOW 0x00000000
#define DYNSEC_RESPONSE_EPERM 0x00000001


#pragma pack(push, 1)
struct dynsec_msg_hdr {
    uint16_t payload;
    uint32_t pid;   // tid
    uint64_t req_id;
    uint32_t event_type;
};

// Response from usermode
struct dynsec_response {
    uint32_t pid;
    uint64_t req_id;
    uint32_t event_type;
    int32_t response;
    uint32_t cache_flags;
};

// Core Exec Context
struct dynsec_exec_msg {
    uint32_t pid;  // tid
    uint32_t tgid; // pid
    uint32_t ppid;
    uint32_t uid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;
    uint64_t sb_magic;
    uint64_t ino;
    uint32_t dev;
    uint16_t path_offset;
    uint16_t path_size;
};

#ifdef __KERNEL__
struct dynsec_exec_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_exec_msg msg;
    char *path;
};
#endif /* __KERNEL__ */

struct dynsec_exec_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_exec_msg msg;
};

// Core Unlink Content
struct dynsec_unlink_msg {
    uint32_t pid;  // tid
    uint32_t tgid; // pid
    uint32_t ppid;
    uint32_t uid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;
    uint64_t sb_magic;
    uint16_t mode;
    uint64_t ino;
    uint32_t dev;
    uint16_t path_offset;
    uint16_t path_size;
    uint64_t parent_ino;
    uint32_t parent_dev;
};

#ifdef __KERNEL__
struct dynsec_unlink_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_unlink_msg msg;
    char *path;
};
#endif /* __KERNEL__ */

struct dynsec_unlink_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_unlink_msg msg;
};

// Core Rename Content
struct dynsec_rename_msg {
    uint32_t pid;  // tid
    uint32_t tgid; // pid
    uint32_t ppid;
    uint32_t uid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;

    uint64_t sb_magic;
    uint32_t dev;

    uint16_t old_mode;
    uint64_t old_ino;
    uint16_t old_path_offset;
    uint16_t old_path_size;
    uint64_t old_parent_ino;

    uint16_t new_mode;
    uint64_t new_ino;
    uint16_t new_path_offset;
    uint16_t new_path_size;
    uint64_t new_parent_ino;
};

#ifdef __KERNEL__
struct dynsec_rename_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_rename_msg msg;
    char *old_path;
    char *new_path;
};
#endif /* __KERNEL__ */

struct dynsec_rename_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_rename_msg msg;
};
#pragma pack(pop)

