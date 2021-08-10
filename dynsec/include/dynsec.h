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
#define DYNSEC_HOOK_TYPE_CLOSE     0x00002000
#define DYNSEC_HOOK_TYPE_TASK_FREE 0x00004000

// Tracepoints
#define DYNSEC_TP_HOOK_TYPE_CLONE       0x00000001
#define DYNSEC_TP_HOOK_TYPE_EXIT        0x00000002
#define DYNSEC_TP_HOOK_TYPE_TASK_FREE   0x00000004

// Event Message Flags aka Report
#define DYNSEC_REPORT_STALL      0x0001
#define DYNSEC_REPORT_INTENT     0x0002
#define DYNSEC_REPORT_AUDIT      0x0004
#define DYNSEC_REPORT_EXITING    0x0008
#define DYNSEC_REPORT_TP         0x0010
#define DYNSEC_REPORT_SELF       0x0020


// Response Type For Stalls
#define DYNSEC_RESPONSE_ALLOW 0x00000000
#define DYNSEC_RESPONSE_EPERM 0x00000001

// For Setattr Event
#define DYNSEC_SETATTR_MODE     (1 << 0)
#define DYNSEC_SETATTR_UID      (1 << 1)
#define DYNSEC_SETATTR_GID      (1 << 2)
#define DYNSEC_SETATTR_SIZE     (1 << 3)
#define DYNSEC_SETATTR_FILE     (1 << 13)
#define DYNSEC_SETATTR_OPEN     (1 << 15)

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
    DYNSEC_EVENT_TYPE_CLOSE,
    DYNSEC_EVENT_TYPE_LINK,
    DYNSEC_EVENT_TYPE_SYMLINK,
    DYNSEC_EVENT_TYPE_SIGNAL,
    DYNSEC_EVENT_TYPE_PTRACE,
    DYNSEC_EVENT_TYPE_MMAP,
    DYNSEC_EVENT_TYPE_CLONE,
    DYNSEC_EVENT_TYPE_EXIT,
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
    uint32_t flags;
};

struct dynsec_blob {
    uint16_t offset;
    uint16_t size;
};

struct dynsec_file {
    uint64_t ino;
    uint32_t dev;
    uint16_t umode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint64_t sb_magic;
    uint64_t parent_ino;
    uint32_t parent_dev;
    uint32_t parent_uid;
    uint32_t parent_gid;
    uint16_t path_offset;
    uint16_t path_size;
};

// Core Exec Context
struct dynsec_exec_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file file;
};

struct dynsec_exec_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_exec_msg msg;
};

// Core Unlink Content
struct dynsec_unlink_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file file;
};

struct dynsec_unlink_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_unlink_msg msg;
};

// Core Rename Content
struct dynsec_rename_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file old_file;
    struct dynsec_file new_file;
};

struct dynsec_rename_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_rename_msg msg;
};

// Core Setattr Content
struct dynsec_setattr_msg {
    struct dynsec_task_ctx task;
    uint32_t attr_mask;
    uint16_t attr_umode;
    uint32_t attr_uid;
    uint32_t attr_gid;
    uint64_t attr_size;
    struct dynsec_file file;
};

struct dynsec_setattr_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_setattr_msg msg;
};

// Core Create/Mkdir Content
struct dynsec_create_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file file;
};

struct dynsec_create_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_create_msg msg;
};

// Core Generic File Content
struct dynsec_file_msg {
    struct dynsec_task_ctx task;
    uint32_t f_mode;
    uint32_t f_flags;
    struct dynsec_file file;
};

struct dynsec_file_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_file_msg msg;
};

// Core Link Content
struct dynsec_link_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file old_file;
    struct dynsec_file new_file;
};

struct dynsec_link_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_link_msg msg;
};

// Core Symlink Content
struct dynsec_symlink_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file file;
    struct dynsec_blob target;
};

struct dynsec_symlink_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_symlink_msg msg;
};

// Core Mmap Content
struct dynsec_mmap_msg {
    struct dynsec_task_ctx task;
    uint64_t mmap_prot;
    uint64_t mmap_flags;
    uint32_t f_mode;
    uint32_t f_flags;
    struct dynsec_file file;
};

struct dynsec_mmap_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_mmap_msg msg;
};

// Core Ptrace Content
struct dynsec_ptrace_msg {
    struct dynsec_task_ctx source;
    struct dynsec_task_ctx target;
};

struct dynsec_ptrace_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_ptrace_msg msg;
};

// Core Signal Content
struct dynsec_signal_msg {
    struct dynsec_task_ctx source;
    int32_t signal;
    struct dynsec_task_ctx target;
};

struct dynsec_signal_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_signal_msg msg;
};

// Core Task Event
struct dynsec_task_msg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_task_ctx task;
};
struct dynsec_task_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_task_msg msg;
};

#pragma pack(pop)

