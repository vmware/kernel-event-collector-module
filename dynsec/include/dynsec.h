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
#define DYNSEC_EVENT_TYPE_SETATTR   0x00000008

// Well see how long this can map 1:1
#define DYNSEC_LSM_bprm_set_creds       DYNSEC_EVENT_TYPE_EXEC
#define DYNSEC_LSM_inode_rename         DYNSEC_EVENT_TYPE_RENAME
#define DYNSEC_LSM_inode_unlink         DYNSEC_EVENT_TYPE_UNLINK
#define DYNSEC_LSM_inode_setattr        DYNSEC_EVENT_TYPE_SETATTR


#define DYNSEC_RESPONSE_ALLOW 0x00000000
#define DYNSEC_RESPONSE_EPERM 0x00000001


#pragma pack(push, 1)
struct dynsec_msg_hdr {
    uint16_t payload;
    uint64_t req_id;
    uint32_t event_type;
};

// Response from usermode
struct dynsec_response {
    uint64_t req_id;
    uint32_t event_type;
    int32_t response;
    uint32_t cache_flags;
};

// Core Exec Context
struct dynsec_exec_msg {
    uint32_t pid;
    uint32_t tgid;
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

#pragma pack(pop)

