// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include "dynsec.h"
#include "factory.h"
#include "task_cache.h"

// Provide Simple Per-Task Level Event Tracking/Caching

// TODO: Clear on Disconnect of Client
// - Add into stall_tbl

struct task_bkt {
    spinlock_t lock;
    u32 size;
    struct list_head list;
};

struct task_key {
    pid_t tid;
};

struct task_entry {
    u32 hash;
    struct task_key key;
    struct list_head list;
    u32 hits;

    // Most recent event observed
    uint64_t last_req_id;
    uint16_t last_report_flags;
    enum dynsec_event_type last_event_type;

    // Most recent event requested to stall
    uint64_t last_stall_req_id;
    enum dynsec_event_type last_stall_event_type;

    // Per-Event Cache Options
    u16 event_caches[DYNSEC_EVENT_TYPE_MAX + 1];

    // Per-Event Counters
    u32 events[DYNSEC_EVENT_TYPE_MAX];
};

struct task_cache {
    struct task_bkt *bkt;
};

#define TASK_MAX_BKT_SZ 10
#define TASK_BUCKET_BITS 11
#define TASK_BUCKETS BIT(TASK_BUCKET_BITS)

static struct task_cache *task_cache = NULL;

int task_cache_enabled = 0;

static inline u32 task_hash(struct task_key *key)
{
    return jhash(key, sizeof(*key), 0);
}
static int task_bucket_index(u32 hash)
{
    return hash & (TASK_BUCKETS - 1);
}

int task_cache_register(void)
{
    u32 i;

    task_cache = kzalloc(sizeof(struct task_cache), GFP_KERNEL);
    if (!task_cache) {
        return -ENOMEM;
    }

    task_cache->bkt =
        kcalloc(TASK_BUCKETS, sizeof(struct task_bkt), GFP_KERNEL);
    if (!task_cache->bkt) {
        kfree(task_cache);
        return -ENOMEM;
    }

    for (i = 0; i < TASK_BUCKETS; i++) {
        spin_lock_init(&task_cache->bkt[i].lock);
        task_cache->bkt[i].size = 0;
        INIT_LIST_HEAD(&task_cache->bkt[i].list);
    }
    task_cache_enabled = 1;
    return 0;
}
static void task_cache_free_entries(void);
void task_cache_shutdown(void)
{
    if (task_cache) {
        // Shutdown Cache
        task_cache_enabled = 0;
        task_cache_free_entries();

        // Iterate through entries and free
        kfree(task_cache);
        task_cache = NULL;
    }
}

static void task_cache_free_entries(void)
{
    struct task_entry *entry, *tmp;
    int i;
    unsigned long flags;

    for (i = 0; i < TASK_BUCKETS; i++) {
        spin_lock_irqsave(&task_cache->bkt[i].lock, flags);
        list_for_each_entry_safe (entry, tmp, &task_cache->bkt[i].list,
                      list) {
            list_del_init(&entry->list);
            kfree(entry);
        }
        task_cache->bkt[i].size = 0;
        spin_unlock_irqrestore(&task_cache->bkt[i].lock, flags);
    }
}

static struct task_entry *__lookup_entry_safe(u32 hash, struct task_key *key,
                                              struct list_head *head)
{
    struct task_entry *entry;
    struct task_entry *tmp;
    list_for_each_entry_safe(entry, tmp, head, list) {
        if (entry->hash == hash && entry->key.tid == key->tid) {
            return entry;
        }
    }
    return NULL;
}

#define task_observed_stall_event(task_entry) \
    (task_entry->last_stall_event_type < DYNSEC_EVENT_TYPE_MAX)

#define event_cache_enabled(mask) \
    (!!(mask & (DYNSEC_CACHE_ENABLE|DYNSEC_CACHE_ENABLE_EXCL|DYNSEC_CACHE_ENABLE_STRICT)))


static inline void __update_entry_data(struct dynsec_event *event,
                                      struct task_entry *entry)
{
    const u16 old_report_flags = event->report_flags;
    const bool is_stall = !!(old_report_flags & DYNSEC_REPORT_STALL);

    entry->hits += 1;

    switch (entry->event_caches[event->event_type])
    {
    case 0:
        break;

    case DYNSEC_CACHE_ENABLE:
        if (is_stall) {
            event->report_flags &= ~(DYNSEC_REPORT_STALL);
            event->report_flags |= DYNSEC_REPORT_CACHED;
        }
        break;

    case DYNSEC_CACHE_ENABLE_EXCL:
        // Disable Cache If Previous STALL Event Is Cacheable
        if (!task_observed_stall_event(entry) ||
            event_cache_enabled(entry->event_caches[entry->last_stall_event_type])) {
            if (is_stall) {
                event->report_flags &= ~(DYNSEC_REPORT_STALL);
                event->report_flags |= DYNSEC_REPORT_CACHED;
            }
        } else {
            entry->event_caches[event->event_type] = 0;
        }
        break;

    case DYNSEC_CACHE_ENABLE_STRICT:
        // Disable Cache On Event If Another Event Type Sent
        if (entry->last_event_type == event->event_type) {
            if (is_stall) {
                event->report_flags &= ~(DYNSEC_REPORT_STALL);
                event->report_flags |= DYNSEC_REPORT_CACHED;
            }
        } else {
            entry->event_caches[event->event_type] = 0;
        }
        break;

    case DYNSEC_CACHE_CLEAR_ON_EVENT:
        memset(entry->event_caches, 0, sizeof(entry->event_caches));
        break;

    default:
        break;
    }

    // Update last known event. Primarily for preactions.
    entry->last_req_id = event->req_id;
    entry->last_event_type = event->event_type;
    entry->last_report_flags = old_report_flags;

    // Update last known stall event
    if (is_stall) {
        entry->last_stall_req_id = event->req_id;
        entry->last_stall_event_type = event->event_type;
    }

    // Per-Task Level Event Counter
    entry->events[event->event_type] += 1;
}

int task_cache_set_last_event(struct dynsec_event *event,
                              uint64_t *prev_req_id,
                              enum dynsec_event_type *prev_event_type,
                              gfp_t mode)
{
    u32 hash;
    unsigned long flags = 0;
    struct task_entry *entry;
    struct task_bkt *bkt;
    int bkt_index;
    struct task_key key = {};

    if (!task_cache_enabled || !event) {
        return -EINVAL;
    }

    if (event->event_type < 0 ||
        event->event_type >= DYNSEC_EVENT_TYPE_MAX) {
        return -EINVAL;
    }

    key.tid = event->tid;
    hash = task_hash(&key);
    bkt_index = task_bucket_index(hash);
    bkt = &(task_cache->bkt[bkt_index]);

    // Lookup Entry
    spin_lock_irqsave(&bkt->lock, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        // Copy over previous event context first
        if (prev_req_id) {
            *prev_req_id = entry->last_req_id;
        }
        if (prev_event_type) {
            *prev_event_type = entry->last_event_type;
        }

        __update_entry_data(event, entry);

        spin_unlock_irqrestore(&bkt->lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&bkt->lock, flags);

    entry = kzalloc(sizeof(*entry), mode);
    if (!entry) {
        return -ENOMEM;
    }
    entry->hash = hash;
    entry->hits = 1;
    memcpy(&entry->key, &key, sizeof(key));

    // Insert New Entry
    spin_lock_irqsave(&bkt->lock, flags);
    if (bkt->size >= TASK_MAX_BKT_SZ) {
        // Remove oldest entry as needed
        struct task_entry *old;
        old = list_entry(bkt->list.prev, struct task_entry, list);
        list_del_init(&old->list);
        list_add(&entry->list, &bkt->list);

        kfree(old);
    } else {
        list_add(&entry->list, &bkt->list);
        bkt->size += 1;
    }

    entry->last_req_id = event->req_id;
    entry->last_event_type = event->event_type;
    entry->last_report_flags = event->report_flags;

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        entry->last_stall_req_id = event->req_id;
        entry->last_stall_event_type = event->event_type;
    } else {
        entry->last_stall_event_type = DYNSEC_EVENT_TYPE_MAX;
    }
    spin_unlock_irqrestore(&bkt->lock, flags);

    return 0;
}

int task_cache_handle_response(struct dynsec_response *response)
{
    u32 hash;
    unsigned long flags = 0;
    struct task_entry *entry;
    struct task_bkt *bkt;
    int bkt_index;
    struct task_key key = {};
    uint32_t cache_flags = 0;
    int ret = -ENOENT;
    unsigned opts_set;

    if (!task_cache_enabled || !response) {
        return -EINVAL;
    }
    if (response->event_type < 0 ||
        response->event_type >= DYNSEC_EVENT_TYPE_MAX) {
        return -EINVAL;
    }

    // Exclude DYNSEC_CACHE_CLEAR from mask to allow
    // clearing before setting an option.
    cache_flags = response->cache_flags;
    cache_flags &= (DYNSEC_CACHE_ENABLE |
                    DYNSEC_CACHE_ENABLE_EXCL |
                    DYNSEC_CACHE_ENABLE_STRICT |
                    DYNSEC_CACHE_DISABLE |
                    DYNSEC_CACHE_CLEAR_ON_EVENT);
    opts_set = hweight32(cache_flags);
    if ((!opts_set || opts_set >= 2) &&
        !(response->cache_flags & DYNSEC_CACHE_CLEAR))
    {
        return -EINVAL;
    }

    key.tid = response->tid;
    hash = task_hash(&key);
    bkt_index = task_bucket_index(hash);
    bkt = &(task_cache->bkt[bkt_index]);

    // Lookup Entry
    spin_lock_irqsave(&bkt->lock, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        ret = 0;

        if (response->cache_flags & DYNSEC_CACHE_CLEAR) {
            memset(entry->event_caches, 0, sizeof(entry->event_caches));
        }

        // Set appropriate event level cache option
        if (cache_flags & DYNSEC_CACHE_DISABLE) {
            entry->event_caches[response->event_type] = 0;
        } else {
            entry->event_caches[response->event_type] = cache_flags;
        }
    }
    spin_unlock_irqrestore(&bkt->lock, flags);

    return ret;
}

void task_cache_clear_response_caches(pid_t tid)
{
    u32 hash;
    unsigned long flags = 0;
    struct task_entry *entry;
    struct task_bkt *bkt;
    int bkt_index;
    struct task_key key = {
        .tid = tid,
    };

    if (!task_cache_enabled || !tid) {
        return;
    }

    hash = task_hash(&key);
    bkt_index = task_bucket_index(hash);
    bkt = &(task_cache->bkt[bkt_index]);

    spin_lock_irqsave(&bkt->lock, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        memset(entry->event_caches, 0, sizeof(entry->event_caches));
    }
    spin_unlock_irqrestore(&bkt->lock, flags);
}

void task_cache_remove_entry(pid_t tid)
{
    u32 hash;
    unsigned long flags = 0;
    struct task_entry *entry;
    struct task_bkt *bkt;
    int bkt_index;
    struct task_key key = {
        .tid = tid,
    };

    if (!task_cache_enabled || !tid) {
        return;
    }

    hash = task_hash(&key);
    bkt_index = task_bucket_index(hash);
    bkt = &(task_cache->bkt[bkt_index]);

    spin_lock_irqsave(&bkt->lock, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        list_del_init(&entry->list);
        bkt->size -= 1;
    }
    spin_unlock_irqrestore(&bkt->lock, flags);
}
