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

enum file_notify__blob_type {
    BLOB_TYPE_RAW,
    BLOB_TYPE_NUL_TERMINATE_STRING,
    BLOB_TYPE_DENTRY_PATH,
    BLOB_TYPE_FULL_PATH,
    BLOB_TYPE_DPATH,

    // Keep last
    BLOB_TYPE_MAX,
};

#define BLOB_TYPE_FLAG__TRUNCATED         0x01
#define BLOB_TYPE_FLAG__LIKELY_TRUNCATED  0x02
// handle case when file was likely deleted and
// we called bpf_d_path. Just requires removing "(deleted)"
// from blob in userspace. This is safer than always
// checking for "(deleted)" in the paths to prevent
// data racing based circumvention.
#define BLOB_TYPE_FLAG__UNLINKED          0x04


struct file_notify__blob_ctx {
    uint8_t type;       // file_notify__blob_type
    uint8_t flags;      // blob type flags/hints
    uint16_t reserved;  // BTF_KIND Info would be cool

    uint16_t size;
    uint16_t offset;
};

// Return the decisions made and place into a bitmap
// and whatever other computations we want to help
// userspace understand our decision.
struct file_notify__decision_vector {
    uint64_t reserved[8];
};

struct file_notify_msg {
    struct file_notify_hdr hdr;

    struct file_notify_task_ctx task_ctx;

    // TODO: Process Context Here
    // File Context
    struct inode_cache_entry inode_entry;

    struct file_notify__blob_ctx path;

    char blob[8192];
};
