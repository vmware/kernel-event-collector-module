/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

#include "dynsec.h"


#pragma pack(push, 1)
struct dynsec_event {
    uint64_t req_id;
    uint32_t type;
    struct list_head list;
};

struct dynsec_exec_event {
    struct dynsec_event event;
    struct dynsec_exec_kmsg kmsg;
};

#pragma pack(pop)

// Exec Event container_of helper
static inline struct dynsec_exec_event *
dynsec_event_to_exec(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_exec_event, event);
}

extern uint16_t get_dynsec_event_payload(struct dynsec_event *dynsec_event);

extern struct dynsec_event *alloc_dynsec_event(uint32_t type, gfp_t mode);

extern void free_dynsec_event(struct dynsec_event *dynsec_event);

extern ssize_t copy_dynsec_event_to_user(const struct dynsec_event *dynsec_event,
                                         char *__user p, size_t count);

// Event fillers
#include <linux/binfmts.h>
extern bool fill_in_bprm_set_creds(struct dynsec_exec_event *exec_event,
                                   const struct linux_binprm *bprm, gfp_t mode);
