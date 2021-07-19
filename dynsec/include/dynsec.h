/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

#define DYNSEC_HOOK_TYPE_EXEC      0x00000001
#define DYNSEC_HOOK_TYPE_RENAME    0x00000002
#define DYNSEC_HOOK_TYPE_UNLINK    0x00000004
#define DYNSEC_HOOK_TYPE_RMDIR     0x00000008
#define DYNSEC_HOOK_TYPE_MKDIR     0x00000010
#define DYNSEC_HOOK_TYPE_CREATE    0x00000020
#define DYNSEC_HOOK_TYPE_SETATTR   0x00000040
#define DYNSEC_HOOK_TYPE_OPEN      0x00000080
#define DYNSEC_HOOK_TYPE_LINK      0x00000100
#define DYNSEC_HOOK_TYPE_SYMLINK   0x00000200
#define DYNSEC_HOOK_TYPE_SIGNAL    0x00000400
#define DYNSEC_HOOK_TYPE_PTRACE    0x00000800
#define DYNSEC_HOOK_TYPE_MMAP      0x00001000


// Event Message Flags aka Report
#define DYNSEC_REPORT_STALL      0x0001
#define DYNSEC_REPORT_INTENT     0x0002
#define DYNSEC_REPORT_AUDIT      0x0004
#define DYNSEC_REPORT_EXITING    0x0008
#define DYNSEC_REPORT_STALL_FAIL 0x0010


// Response Type For Stalls
#define DYNSEC_RESPONSE_ALLOW 0x00000000
#define DYNSEC_RESPONSE_EPERM 0x00000001


#pragma pack(push, 1)
// Event Message Types
enum dynsec_event_type {
    DYNSEC_EVENT_TYPE_EXEC,
    DYNSEC_EVENT_TYPE_RENAME,
    DYNSEC_EVENT_TYPE_UNLINK,
    DYNSEC_EVENT_TYPE_RMDIR,
    DYNSEC_EVENT_TYPE_MKDIR,
    DYNSEC_EVENT_TYPE_CREATE,
    DYNSEC_EVENT_TYPE_SETATTR,
    DYNSEC_EVENT_TYPE_OPEN,
    DYNSEC_EVENT_TYPE_LINK,
    DYNSEC_EVENT_TYPE_SYMLINK,
    DYNSEC_EVENT_TYPE_SIGNAL,
    DYNSEC_EVENT_TYPE_PTRACE,
    DYNSEC_EVENT_TYPE_MMAP,
    DYNSEC_EVENT_TYPE_HEALTH,
    DYNSEC_EVENT_TYPE_GENERIC_AUDIT,
    DYNSEC_EVENT_TYPE_GENERIC_DEBUG,
    DYNSEC_EVENT_TYPE_MAX,
};

struct dynsec_msg_hdr {
    uint16_t payload;
    uint16_t report_flags;
    uint32_t hook_type;  // Context for non-stalling events
    uint32_t tid;
    uint64_t req_id;
    enum dynsec_event_type event_type;
};

// Response from usermode
struct dynsec_response {
    uint32_t tid;
    uint64_t req_id;
    enum dynsec_event_type event_type;
    int32_t response;
    uint32_t cache_flags;
};

struct dynsec_task_ctx {
    uint32_t tid;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;
    uint32_t mnt_ns;
};

// Core Exec Context
struct dynsec_exec_msg {
    struct dynsec_task_ctx task;
    uint64_t sb_magic;
    uint64_t ino;
    uint32_t dev;
    uint16_t path_offset;
    uint16_t path_size;
};

struct dynsec_exec_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_exec_msg msg;
};

// Core Unlink Content
struct dynsec_unlink_msg {
    struct dynsec_task_ctx task;

    uint64_t sb_magic;
    uint16_t mode;

    uint64_t ino;
    uint32_t dev;
    uint16_t path_offset;
    uint16_t path_size;
    uint64_t parent_ino;
};

struct dynsec_unlink_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_unlink_msg msg;
};

// Core Rename Content
struct dynsec_rename_msg {
    struct dynsec_task_ctx task;

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

struct dynsec_rename_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_rename_msg msg;
};
#pragma pack(pop)

