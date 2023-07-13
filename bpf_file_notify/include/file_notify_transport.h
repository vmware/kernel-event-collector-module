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
#define INODE_TYPE_LABEL_EXE             0x0010
    uint16_t type_flags;

    uint64_t total_deny;
    uint64_t total_seen;

    // Add more things here
};

