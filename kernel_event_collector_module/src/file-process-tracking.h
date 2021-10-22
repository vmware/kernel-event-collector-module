/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/types.h>
#include "priv.h"
#include "hash-table-generic.h"

typedef enum FILE_PROCESS_STATUS {
    OPENED, //File has been opened, and written before
    CLOSED  //File is closed.
} FILE_PROCESS_STATUS;

typedef struct FILE_PROCESS_KEY {
    uint32_t            pid;
    uint64_t            device;
    uint64_t            inode;
} FILE_PROCESS_KEY;

typedef struct FILE_PROCESS_VALUE {
    HashTableNode       node;
    FILE_PROCESS_KEY    key;
    pid_t               pid;
    FILE_PROCESS_STATUS status;
    bool                didReadType;
    bool                isSpecialFile;
    char               *path;
    atomic64_t          reference_count;
} FILE_PROCESS_VALUE;

void ec_file_process_put_ref(FILE_PROCESS_VALUE *value, ProcessContext *context);

bool ec_file_tracking_init(ProcessContext *context);
void ec_file_tracking_shutdown(ProcessContext *context);
FILE_PROCESS_VALUE *ec_file_process_get(
    uint32_t        pid,
    uint64_t        device,
    uint64_t        inode,
    ProcessContext *context);
FILE_PROCESS_VALUE *ec_file_process_status_open(
    uint32_t        pid,
    uint64_t        device,
    uint64_t        inode,
    char           *path,
    bool            isSpecialFile,
    ProcessContext *context);
void ec_file_process_status_close(
    uint32_t        pid,
    uint64_t        device,
    uint64_t        inode,
    ProcessContext *context);
