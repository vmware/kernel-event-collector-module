// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include "dynsec.h"
#include "factory.h"
#include "task_cache.h"

// Provide Simple Per-Task Level Event Tracking/Caching

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
    struct event_track last;

    // Most recent event requested to stall
    struct event_track last_stall;

    // Per-Event Cache Options
    u16 event_caches[DYNSEC_EVENT_TYPE_MAX + 1];

    // Per-Event Counters
    u32 events[DYNSEC_EVENT_TYPE_MAX];
};

struct task_cache {
    bool enabled;
    bool used_vmalloc;
    struct task_bkt *bkt;
    u32 seed;
};

#define TASK_MAX_BKT_SZ 8
#define TASK_BUCKET_BITS 14
#define TASK_BUCKETS BIT(TASK_BUCKET_BITS)

static struct task_cache *task_cache = NULL;

static inline u32 task_hash(struct task_key *key, u32 secret)
{
    return jhash(key, sizeof(*key), secret);
}
static int task_bucket_index(u32 hash)
{
    return hash & (TASK_BUCKETS - 1);
}

static void task_cache_free_entries(void)
{
    struct task_entry *entry, *tmp;
    int i;
    unsigned long flags;

    if (!task_cache || !task_cache->bkt) {
        return;
    }

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

int task_cache_register(void)
{
    u32 i;

    task_cache = kzalloc(sizeof(struct task_cache), GFP_KERNEL);
    if (!task_cache) {
        return -ENOMEM;
    }

    task_cache->bkt =
        kcalloc(TASK_BUCKETS, sizeof(struct task_bkt), GFP_KERNEL);
    if (task_cache->bkt) {
        task_cache->used_vmalloc = false;
    } else {
        task_cache->bkt = vmalloc(TASK_BUCKETS * sizeof(struct task_bkt));
        if (!task_cache->bkt) {
            kfree(task_cache);
            task_cache = NULL;
            return -ENOMEM;
        }
        task_cache->used_vmalloc = true;
        memset(task_cache->bkt, 0,
               TASK_BUCKETS * sizeof(struct task_bkt));
    }

    for (i = 0; i < TASK_BUCKETS; i++) {
        spin_lock_init(&task_cache->bkt[i].lock);
        task_cache->bkt[i].size = 0;
        INIT_LIST_HEAD(&task_cache->bkt[i].list);
    }

    get_random_bytes(&task_cache->seed, sizeof(task_cache->seed));

    task_cache->enabled = 1;
    return 0;
}

void task_cache_clear(void)
{
    task_cache_free_entries();
}

void task_cache_disable(void)
{
    if (task_cache && task_cache->enabled) {
        task_cache_clear();
        task_cache->enabled = false;
    }
}

void task_cache_enable(void)
{
    if (task_cache && task_cache->bkt) {
        task_cache->enabled = true;
    }
}

void task_cache_shutdown(void)
{
    if (task_cache) {
        // Shutdown Cache
        task_cache->enabled = false;
        task_cache_free_entries();

        // Iterate through entries and free
        if (task_cache->bkt) {
            if (task_cache->used_vmalloc) {
                vfree(task_cache->bkt);
            } else {
                kfree(task_cache->bkt);
            }
            task_cache->bkt = NULL;
        }

        kfree(task_cache);
        task_cache = NULL;
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
    (task_entry->last_stall.event_type < DYNSEC_EVENT_TYPE_MAX)

#define event_cache_enabled(mask) \
    (!!(mask & (DYNSEC_CACHE_ENABLE|DYNSEC_CACHE_ENABLE_EXCL|DYNSEC_CACHE_ENABLE_STRICT)))


static inline void __update_entry_data(struct event_track *event,
                                       struct task_entry *entry)
{
    const u16 old_report_flags = event->report_flags;
    const bool is_stall = !!(old_report_flags & DYNSEC_REPORT_STALL);

    entry->hits += 1;

    // If not reportable then only set last event and touch nothing else
    if (!(event->track_flags & TRACK_EVENT_REPORTABLE)) {
        memcpy(&entry->last, event, sizeof(*event));
        return;
    }

    switch (entry->event_caches[event->event_type])
    {
    case 0:
        break;

    case DYNSEC_CACHE_ENABLE:
        if (is_stall) {
            event->report_flags &= ~(DYNSEC_REPORT_STALL);
            event->report_flags |= DYNSEC_REPORT_CACHED;
            event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
        }
        break;

    case DYNSEC_CACHE_ENABLE_EXCL:
        // Disable Cache If Previous STALL Event WAS NOT Cacheable
        if (!task_observed_stall_event(entry) ||
            event_cache_enabled(entry->event_caches[entry->last_stall.event_type])) {
            if (is_stall) {
                event->report_flags &= ~(DYNSEC_REPORT_STALL);
                event->report_flags |= DYNSEC_REPORT_CACHED;
                event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
            }
        } else {
            entry->event_caches[event->event_type] = 0;
        }
        break;

    case DYNSEC_CACHE_ENABLE_STRICT:
        // Disable Cache On Event If Another Event Type Sent
        if (entry->last.event_type == event->event_type) {
            if (is_stall) {
                event->report_flags &= ~(DYNSEC_REPORT_STALL);
                event->report_flags |= DYNSEC_REPORT_CACHED;
                event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
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
    memcpy(&entry->last, event, sizeof(*event));

    // Update last known stall event
    if (is_stall) {
        memcpy(&entry->last_stall, event, sizeof(*event));
    }

    // Per-Task Level Event Counter
    if (!(old_report_flags & DYNSEC_REPORT_INTENT)) {
        entry->events[event->event_type] += 1;
    }
}

int task_cache_set_last_event(pid_t tid,
                              struct event_track *event,
                              struct event_track *prev_event,
                              gfp_t mode)
{
    u32 hash;
    unsigned long flags = 0;
    struct task_entry *entry;
    struct task_bkt *bkt;
    int bkt_index;
    struct task_key key = {};

    if (!task_cache || !task_cache->enabled || !event || !tid) {
        return -EINVAL;
    }

    if (event->event_type < 0 ||
        event->event_type >= DYNSEC_EVENT_TYPE_MAX) {
        return -EINVAL;
    }

    key.tid = tid;
    hash = task_hash(&key, task_cache->seed);
    bkt_index = task_bucket_index(hash);
    bkt = &(task_cache->bkt[bkt_index]);

    // Lookup Entry
    spin_lock_irqsave(&bkt->lock, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        // Copy over previous event context first
        if (prev_event) {
            memcpy(prev_event, &entry->last, sizeof(*prev_event));
        }

        // TODO: place in front of queue
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
    INIT_LIST_HEAD(&entry->list);

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

    memcpy(&entry->last, event, sizeof(*event));

    if (event->report_flags & DYNSEC_REPORT_STALL) {
        memcpy(&entry->last_stall, event, sizeof(*event));
    } else {
        entry->last_stall.event_type = DYNSEC_EVENT_TYPE_MAX;
    }
    spin_unlock_irqrestore(&bkt->lock, flags);

    return -ENOENT;
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

    if (!task_cache || !task_cache->enabled || !response) {
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
    hash = task_hash(&key, task_cache->seed);
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

    if (!task_cache || !task_cache->enabled || !tid) {
        return;
    }

    hash = task_hash(&key, task_cache->seed);
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
    struct task_entry *entry = NULL;
    struct task_bkt *bkt;
    int bkt_index;
    struct task_key key = {
        .tid = tid,
    };

    if (!task_cache || !task_cache->enabled || !tid) {
        return;
    }

    hash = task_hash(&key, task_cache->seed);
    bkt_index = task_bucket_index(hash);
    bkt = &(task_cache->bkt[bkt_index]);

    spin_lock_irqsave(&bkt->lock, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        list_del_init(&entry->list);
        bkt->size -= 1;
    }
    spin_unlock_irqrestore(&bkt->lock, flags);

    if (entry) {
        kfree(entry);
    }
}
