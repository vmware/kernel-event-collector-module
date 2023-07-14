/* Copyright 2023 VMware Inc.  All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

enum inode_cache_event_type {
    OPEN,
    UNLINK,
    LINK,
    RENAME,
    WRITE,
    FREE,
};


struct inode_cache_entry {
#define INODE_TYPE_LABEL_BANNED          0x0001
#define INODE_TYPE_LABEL_INTERESTING     0x0002
#define INODE_TYPE_LABEL_IGNORE          0x0004
#define INODE_TYPE_LABEL_EXE             0x0010
    uint16_t type_flags;
    uint16_t report_mask;
    uint64_t total_deny;
    uint64_t total_seen;

    // Add more things here
};

struct file_notify_hdr {
    uint64_t ts;
    uint32_t payload;
    uint16_t event_type;
#define FILE_NOTIFY_REASON_DENY     0x0001
#define FILE_NOTIFY_REASON_NOTIFY   0x0002
    uint16_t report_flags;
};

struct file_notify_task_ctx {
    uint32_t tid;
    uint32_t pid;
    char comm[16];
};

struct file_notify_msg {
    struct file_notify_hdr hdr;

    struct file_notify_task_ctx task_ctx;

    // TODO: Process Context Here
    // File Context
    struct inode_cache_entry inode_entry;

    uint16_t path_size;
    uint16_t path_offset;

    char blob[8192];
};
