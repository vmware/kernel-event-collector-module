/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

#include "dynsec.h"
#include "config.h"
#include <linux/irq_work.h>
#include <linux/ktime.h>

struct stall_bkt {
    spinlock_t lock;
    u32 size;
    struct list_head list;
};

#pragma pack(push, 1)
// Sync fields with `struct dynsec_event`
struct stall_key {
    uint32_t tid;
    uint64_t req_id;
    enum dynsec_event_type event_type;
};
#pragma pack(pop)

struct stall_entry {
    u32 hash;
    struct stall_key key;
    struct list_head list;

// Task is stalling
#define DYNSEC_STALL_MODE_STALL     0x00000001
// Resume normal execution
#define DYNSEC_STALL_MODE_RESUME    0x00000002
// Stalling was disabled
#define DYNSEC_STALL_MODE_DISABLE   0x00000004
// Client disconnect or kmod shutdown
#define DYNSEC_STALL_MODE_SHUTDOWN  0x00000008
    u32 mode;  // switch to atomic or test_bit/set_bit?

    // time event got added to queue
    ktime_t start; // rough duration of entry in tbl/stalled

    wait_queue_head_t wq; // Optionally we could have this be per-bucket not per-entry

    unsigned long inode_addr;
    spinlock_t lock;    // likely not needed but shouldn't hurt
    int response;
    unsigned int stall_timeout;

    // Extra DynSec event header data
    uint16_t report_flags;
    uint64_t intent_req_id;
};

// TODO check ktime_get_raw
#define dynsec_current_ktime  ktime_get_real()

struct stall_q {
    spinlock_t lock;
    u32 size;
    struct list_head list;
    wait_queue_head_t wq;
    wait_queue_head_t pre_wq;
    struct irq_work defer_wakeup;
};

struct stall_tbl {
    bool enabled;
    bool used_vmalloc;
    u32 secret;
    struct stall_bkt *bkt;

    pid_t tgid;
    struct stall_q queue;
};

struct dynsec_event;

static inline bool stall_tbl_enabled(struct stall_tbl *tbl)
{
    return (tbl && tbl->enabled);
}

static inline bool hooks_enabled(struct stall_tbl *tbl)
{
    return !bypass_mode_enabled() && stall_tbl_enabled(tbl);
}

extern struct stall_tbl *stall_tbl_alloc(gfp_t mode);

extern int stall_tbl_resume(struct stall_tbl *tbl, struct stall_key *key,
                            int response, unsigned long inode_cache_flags,
                            unsigned int overrided_stall_timeout);

extern void stall_tbl_shutdown(struct stall_tbl *stbl);

extern void stall_tbl_disable(struct stall_tbl *tbl);

extern void stall_tbl_enable(struct stall_tbl *tbl);

extern struct stall_entry *
stall_tbl_insert(struct stall_tbl *tbl, struct dynsec_event *event, gfp_t mode);

extern u32 enqueue_nonstall_event(struct stall_tbl *tbl, struct dynsec_event *event);

extern u32 enqueue_nonstall_event_no_notify(struct stall_tbl *tbl,
                                            struct dynsec_event *event);

extern int stall_tbl_remove_entry(struct stall_tbl *tbl, struct stall_entry *entry);

extern u32 stall_queue_size(struct stall_tbl *tbl);

extern struct dynsec_event *stall_queue_shift(struct stall_tbl *tbl, size_t space);

extern void stall_tbl_display_buckets(struct stall_tbl *stall_tbl, struct seq_file *m);
extern void stall_tbl_wait_statistics(struct seq_file *m);
