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
    CB_FILE_TYPE        fileType;
    bool                didReadType;
    bool                isSpecialFile;
    char *path;
} FILE_PROCESS_VALUE;


bool file_process_tracking_init(ProcessContext *context);
void file_process_tracking_shutdown(ProcessContext *context);
FILE_PROCESS_VALUE *file_process_status(uint64_t device, uint64_t inode, uint32_t pid, ProcessContext *context);
bool file_process_status_update(uint64_t device, uint64_t inode, uint32_t pid, FILE_PROCESS_VALUE *processValue, ProcessContext *context);
FILE_PROCESS_VALUE *file_process_status_open(uint64_t       device,
                                             uint64_t       inode,
                                             uint32_t       pid,
                                             char *path,
                                             bool           isSpecialFile,
                                             ProcessContext *context);
void file_process_status_close(uint64_t device, uint64_t inode, uint32_t pid, ProcessContext *context);
void check_open_file_list_on_exit(CB_RBTREE *tree, ProcessContext *context);


void file_process_tree_init(void **tree, ProcessContext *context);
void file_process_tree_destroy(void **tree, ProcessContext *context);
