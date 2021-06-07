/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

#include "dynsec.h"


#pragma pack(push, 1)
struct dynsec_event {
    uint64_t req_id;
    uint32_t event_type;
    struct list_head list;
};

struct dynsec_exec_event {
    struct dynsec_event event;
    struct dynsec_exec_kmsg kmsg;
};

struct dynsec_unlink_event {
    struct dynsec_event event;
    struct dynsec_unlink_kmsg kmsg;
};

struct dynsec_rename_event {
    struct dynsec_event event;
    struct dynsec_rename_kmsg kmsg;
};
#pragma pack(pop)

// Exec Event container_of helper
static inline struct dynsec_exec_event *
dynsec_event_to_exec(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_exec_event, event);
}

static inline struct dynsec_unlink_event *
dynsec_event_to_unlink(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_unlink_event, event);
}

static inline struct dynsec_rename_event *
dynsec_event_to_rename(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_rename_event, event);
}

extern uint16_t get_dynsec_event_payload(struct dynsec_event *dynsec_event);

extern struct dynsec_event *alloc_dynsec_event(uint32_t event_type, gfp_t mode);

extern void free_dynsec_event(struct dynsec_event *dynsec_event);

extern ssize_t copy_dynsec_event_to_user(const struct dynsec_event *dynsec_event,
                                         char *__user p, size_t count);

// Event fillers
#include <linux/binfmts.h>
extern bool fill_in_bprm_set_creds(struct dynsec_exec_event *exec_event,
                                   const struct linux_binprm *bprm, gfp_t mode);

extern bool fill_in_inode_unlink(struct dynsec_unlink_event *unlink_event,
                          struct inode *dir, struct dentry *dentry, gfp_t mode);

extern bool fill_in_inode_rename(struct dynsec_rename_event *rename_event,
                                 struct inode *old_dir, struct dentry *old_dentry,
                                 struct inode *new_dir, struct dentry *new_dentry,
                                 gfp_t mode);
