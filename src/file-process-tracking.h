/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/types.h>
#include "priv.h"
#include "rbtree-helper.h"

typedef enum FILE_PROCESS_STATUS {
    OPENED, //File has been opened, and written before
    CLOSED  //File is closed.
} FILE_PROCESS_STATUS;

typedef struct FILE_PROCESS_KEY {
    uint64_t            device;
    uint64_t            inode;
} FILE_PROCESS_KEY;

typedef struct FILE_PROCESS_VALUE {
    struct rb_node      node;
    FILE_PROCESS_KEY    key;
    pid_t               pid;
    FILE_PROCESS_STATUS status;
    bool                didReadType;
    bool                isSpecialFile;
    char               *path;
    atomic64_t          reference_count;
} FILE_PROCESS_VALUE;

void ec_file_process_get_ref(FILE_PROCESS_VALUE *value, ProcessContext *context);
void ec_file_process_put_ref(FILE_PROCESS_VALUE *value, ProcessContext *context);

bool ec_file_process_tracking_init(ProcessContext *context);
void ec_file_process_tracking_shutdown(ProcessContext *context);
FILE_PROCESS_VALUE *ec_file_process_status(uint64_t device, uint64_t inode, uint32_t pid, ProcessContext *context);
FILE_PROCESS_VALUE *ec_file_process_status_open(uint64_t       device,
                                             uint64_t       inode,
                                             uint32_t       pid,
                                             char *path,
                                             bool           isSpecialFile,
                                             ProcessContext *context);
void ec_file_process_status_close(uint64_t device, uint64_t inode, uint32_t pid, ProcessContext *context);
void ec_check_open_file_list_on_exit(CB_RBTREE *tree, ProcessContext *context);


void ec_file_process_tree_init(void **tree, ProcessContext *context);
void ec_file_process_tree_destroy(void **tree, ProcessContext *context);
