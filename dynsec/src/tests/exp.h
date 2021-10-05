/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

#include "dynsec.h"
#include <stdbool.h>

struct exp_dynsec_file {
    uint32_t exp_mask;
    uint32_t err_mask;
    uint32_t act_mask;
    struct dynsec_file file;
};
// Bitmap values to compute the state of the various fields
#define EXP_FILE_INO                    0x00000001
#define EXP_FILE_DEV                    0x00000002
#define EXP_FILE_UMODE_TYPE             0x00000004
#define EXP_FILE_UMODE_PERMS            0x00000008
#define EXP_FILE_UID                    0x00000010
#define EXP_FILE_GID                    0x00000020
#define EXP_FILE_SIZE                   0x00000040
#define EXP_FILE_SB_MAGIC               0x00000080
#define EXP_FILE_PARENT_INO             0x00000100
#define EXP_FILE_PARENT_DEV             0x00000200
#define EXP_FILE_PARENT_UID             0x00000400
#define EXP_FILE_PARENT_GID             0x00000800
#define EXP_FILE_PARENT_UMODE_TYPE      0x00001000
#define EXP_FILE_PARENT_UMODE_PERMS     0x00002000
#define EXP_FILE_PATH_SIZE              0x00004000
#define EXP_FILE_PATH_FULL              0x00008000
#define EXP_FILE_PATH_DENTRY            0x00010000
#define EXP_FILE_PATH_RAW               0x00020000
#define EXP_FILE_POSIX_ACL              0x00040000
#define EXP_FILE_DELETED                0x00080000
#define EXP_FILE_NLINK                  0x00100000
// Helpers to make FILE_ATTR to fields available
#define EXP_FILE_ATTR_INODE (EXP_FILE_INO \
    | EXP_FILE_UMODE_TYPE \
    | EXP_FILE_UMODE_PERMS \
    | EXP_FILE_UID \
    | EXP_FILE_GID \
    | EXP_FILE_SIZE \
    | EXP_FILE_NLINK \
)
#define EXP_FILE_ATTR_DEVICE (EXP_FILE_DEV | EXP_FILE_SB_MAGIC)
#define EXP_FILE_ATTR_PARENT_INODE (EXP_FILE_PARENT_INO \
    | EXP_FILE_PARENT_UMODE_TYPE \
    | EXP_FILE_PARENT_UMODE_PERMS \
    | EXP_FILE_PARENT_UID \
    | EXP_FILE_PARENT_GID \
)


struct exp_dynsec_msg_hdr {
    uint32_t exp_mask;
    uint32_t err_mask;
    uint32_t act_mask;
    struct dynsec_msg_hdr hdr;
};
#define EXP_HDR_EVENT_TYPE              0x00000001
#define EXP_HDR_TID                     0x00000002
#define EXP_HDR_INTENT_REQ_ID           0x00000004
#define EXP_HDR_REPORT_STALL            0x00000008
#define EXP_HDR_REPORT_INTENT           0x00000010
#define EXP_HDR_REPORT_SELF             0x00000020
#define EXP_HDR_REPORT_CACHED           0x00000040


struct exp_dynsec_task_ctx {
    uint32_t exp_mask;
    uint32_t err_mask;
    uint32_t act_mask;
    struct dynsec_task_ctx task;
};
#define EXP_TASK_TID                        0x00000001
#define EXP_TASK_PID                        0x00000002
#define EXP_TASK_PPID                       0x00000004
#define EXP_TASK_REAL_PPID                  0x00000008
#define EXP_TASK_UID                        0x00000010
#define EXP_TASK_EUID                       0x00000020
#define EXP_TASK_GID                        0x00000040
#define EXP_TASK_EGID                       0x00000080
#define EXP_TASK_MNT_NS                     0x00000100
#define EXP_TASK_FLAGS                      0x00000200
#define EXP_TASK_START_TIME                 0x00000400
#define EXP_TASK_IN_EXECVE                  0x00000800
#define EXP_TASK_HAS_MM                     0x00001000
#define EXP_TASK_IMPRECISE_START_TIME       0x00002000
#define EXP_TASK_HAS_MNT_NS                 0x00004000


// This could get complicate fast, so lets keep it basic
// matching types.
enum MATCH_BY {
    // Match the first occurence in a list
    MATCH_BY_FIRST_ANY,
    // Match explicitly in sequence
    MATCH_BY_SEQ,
    // Match by greatest computed match in list
    MATCH_BY_GREATEST,
    // Match by weakest computed match
    MATCH_BY_WEAKEST
};

struct match_obj {
    struct exp_dynsec_msg_hdr hdr;
    struct dynsec_msg_hdr *act_hdr;
    unsigned long total_matched;
};
struct matches {
    enum MATCH_BY match_type;
    struct match_obj *match;
    size_t count;
    unsigned long total_found;
};

extern void release_matches(struct matches *matches);
extern bool find_match(struct matches *matches,
                       const struct dynsec_msg_hdr *act_hdr);
extern bool match_event(struct match_obj *obj,
                        const struct dynsec_msg_hdr *act_hdr);
