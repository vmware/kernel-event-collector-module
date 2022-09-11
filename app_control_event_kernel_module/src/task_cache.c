// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
#include <linux/sched/task.h>
#endif
#include "dynsec.h"
#include "factory.h"
#include "task_cache.h"
#include "config.h"
#include "task_utils.h"


// Purpose for this file:
//  - Tracking the last known event to keep track of intent ids
//    - Dirtying last known events as well
//  - Task Caching/Labeling Options
//    - Cache/Labeling is kind of interchangable (should fix)
//    - Per-task-event level options
//    - Per-task level options

// Generally only Intent events should be required to create an entry,
// unless for some exceptions.
//  - Task Labeling for the parent is enabled and inheritable
//  - A new task is a thread not a main process/thread.


//
// Inheritability Examples
//
// Proc A (Inherit Set) -- Fork --> Proc B (Unset Inherit Bit)
//
// Main Thread A -- Clone --> Child Thread C (Retains Same Bits)
//
// Proc A (Recurse Set) -- Fork --> Proc D (Retains Same Bits)
//
// Proc A (No Inherit Opt) -- Fork --> Proc E (Unlabeled)
//

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

    // Task Level Label Options
    u32 task_label_flags;

    // Per-Event Label Options
    u32 event_caches[DYNSEC_EVENT_TYPE_TASK_DUMP];
};

struct task_cache {
    bool enabled;
    bool used_vmalloc;
    struct task_bkt *bkt;
    u32 seed;
};

#define TASK_MAX_BKT_SZ 32
#define TASK_BUCKET_BITS 16
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
    u32 total_entries = 0;
    u32 bkts_used = 0;

    if (!task_cache || !task_cache->bkt) {
        return;
    }

    for (i = 0; i < TASK_BUCKETS; i++) {
        u32 size = 0;

        spin_lock_irqsave(&task_cache->bkt[i].lock, flags);
        size = task_cache->bkt[i].size;
        list_for_each_entry_safe (entry, tmp, &task_cache->bkt[i].list,
                      list) {
            list_del_init(&entry->list);
            kfree(entry);
        }
        task_cache->bkt[i].size = 0;
        spin_unlock_irqrestore(&task_cache->bkt[i].lock, flags);

        total_entries += size;
        if (size) {
            bkts_used += 1;
        }
    }

    pr_debug("task hashtbl: entries:%u bkts used:%u\n",
            total_entries, bkts_used);
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
        cond_resched();
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
    (task_entry->last_stall.event_type < DYNSEC_EVENT_TYPE_TASK_DUMP)

#define event_cache_enabled(mask) \
    (!!(mask & (DYNSEC_CACHE_ENABLE|DYNSEC_CACHE_ENABLE_EXCL|DYNSEC_CACHE_ENABLE_STRICT)))


static inline void __update_entry_data(struct event_track *event,
                                       struct task_entry *entry)
{
    const u16 old_report_flags = event->report_flags;
    const bool is_stall = !!(old_report_flags & DYNSEC_REPORT_STALL);
    bool is_ignore = false;
    u32 event_mask;

    entry->hits += 1;

    BUILD_BUG_ON(ARRAY_SIZE(entry->event_caches) > DYNSEC_EVENT_TYPE_TASK_DUMP);

    // If not reportable then only set last event and touch nothing else
    if (!(event->track_flags & TRACK_EVENT_REPORTABLE)) {
        memcpy(&entry->last, event, sizeof(*event));
        return;
    }

    // Check Task Level Options First
    if (entry->task_label_flags & DYNSEC_CACHE_ENABLE) {
        if ((entry->task_label_flags & DYNSEC_CACHE_IGNORE)) {
            event->report_flags &= ~(DYNSEC_REPORT_STALL);
            event->report_flags |= DYNSEC_REPORT_IGNORE;
            event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
        } else {
            event->report_flags &= ~(DYNSEC_REPORT_STALL);
            event->report_flags |= DYNSEC_REPORT_CACHED;
            event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
        }
        goto update_on_out;
    }

    // Chop of ignore flag or flags not permitted
    event_mask = entry->event_caches[event->event_type];
    if ((event_mask & DYNSEC_CACHE_IGNORE)) {
        is_ignore = true;
    }
    event_mask &= ~(DYNSEC_CACHE_IGNORE);

    switch (event_mask)
    {
    case 0:
        break;

    case DYNSEC_CACHE_ENABLE:
        if (is_ignore) {
            event->report_flags &= ~(DYNSEC_REPORT_STALL);
            event->report_flags |= DYNSEC_REPORT_IGNORE;
            event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
        } else {
            event->report_flags &= ~(DYNSEC_REPORT_STALL);
            event->report_flags |= DYNSEC_REPORT_CACHED;
            event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
        }
        break;

    case DYNSEC_CACHE_ENABLE_EXCL:
        // Disable Cache If Previous STALL Event WAS NOT Cacheable
        if (!task_observed_stall_event(entry) ||
            event_cache_enabled(entry->event_caches[entry->last_stall.event_type])) {
            if (is_ignore) {
                event->report_flags &= ~(DYNSEC_REPORT_STALL);
                event->report_flags |= DYNSEC_REPORT_IGNORE;
                event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
            } else {
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
            if (is_ignore) {
                event->report_flags &= ~(DYNSEC_REPORT_STALL);
                event->report_flags |= DYNSEC_REPORT_IGNORE;
                event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
            } else {
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

update_on_out:

    // Update last known event. Primarily for preactions.
    memcpy(&entry->last, event, sizeof(*event));

    // Update last known stall event
    if (is_stall) {
        memcpy(&entry->last_stall, event, sizeof(*event));
    }

    // // Per-Task Level Event Counter
    // if (!(old_report_flags & DYNSEC_REPORT_INTENT)) {
    //     entry->events[event->event_type] += 1;
    // }
}

static bool find_parent_task_labels(pid_t parent_pid, u32 *parent_task_label)
{
    u32 hash;
    unsigned long flags = 0;
    struct task_entry *entry;
    struct task_bkt *bkt;
    int bkt_index;
    struct task_key key = {};
    bool found = false;

    if (!parent_pid) {
        return false;
    }

    key.tid = parent_pid;
    hash = task_hash(&key, task_cache->seed);
    bkt_index = task_bucket_index(hash);
    bkt = &(task_cache->bkt[bkt_index]);

    spin_lock_irqsave(&bkt->lock, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        found = true;
        if (parent_task_label) {
            *parent_task_label = entry->task_label_flags;
        }
    }
    spin_unlock_irqrestore(&bkt->lock, flags);

    return found;
}

// Helper to DYNSEC_IOC_LABEL_TASK
static int set_task_label_flags(pid_t tid, u32 task_label_flags, gfp_t mode)
{
    u32 hash;
    unsigned long flags = 0;
    struct task_bkt *bkt;
    int bkt_index;
    struct task_key key = {
        .tid = tid,
    };
    int ret = -ENOENT;
    struct task_entry *old_entry = NULL;
    struct task_entry *new_entry = NULL;


    hash = task_hash(&key, task_cache->seed);
    bkt_index = task_bucket_index(hash);
    bkt = &(task_cache->bkt[bkt_index]);

    // Preallocate an entry just in case. We call this
    // from userspace so doesn't have to be super fast.
    new_entry = kzalloc(sizeof(*new_entry), mode);
    if (new_entry) {
        new_entry->hash = hash;
        new_entry->hits = 1;
        memcpy(&new_entry->key, &key, sizeof(key));
        INIT_LIST_HEAD(&new_entry->list);

        new_entry->last.event_type = DYNSEC_EVENT_TYPE_MAX;
        new_entry->task_label_flags = task_label_flags;
        new_entry->last_stall.event_type = DYNSEC_EVENT_TYPE_MAX;
    } else {
        ret = -ENOMEM;
    }

    spin_lock_irqsave(&bkt->lock, flags);
    old_entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (old_entry) {
        ret = 0;
        old_entry->task_label_flags = task_label_flags;
        memset(old_entry->event_caches, 0, sizeof(old_entry->event_caches));
    }
    // Use preallocated entry
    else if (new_entry) {
        ret = 0;
        if (bkt->size >= TASK_MAX_BKT_SZ) {
            // Remove oldest entry as needed
            struct task_entry *old;
            old = list_entry(bkt->list.prev, struct task_entry, list);
            list_del_init(&old->list);
            list_add(&new_entry->list, &bkt->list);

            kfree(old);
        } else {
            list_add(&new_entry->list, &bkt->list);
            bkt->size += 1;
        }
        // Set to NULL to ensure we don't free it
        new_entry = NULL;
    }
    spin_unlock_irqrestore(&bkt->lock, flags);

    // Release preallocated entry if we did not use it
    if (new_entry) {
        kfree(new_entry);
    }

    pr_debug("%s: %#x for tid:%d\n", __func__, task_label_flags, tid);

    return ret;
}

int handle_task_label_ioc(const struct dynsec_label_task_hdr *hdr)
{
    int ret = -EINVAL;
    pid_t tid = 0;
    struct task_struct *task = NULL;
    u32 task_label_flags = 0;

    if (!task_cache || !task_cache->enabled) {
        return -EINVAL;
    }
    if (!hdr || !hdr->tid) {
        return -EINVAL;
    }

    task_label_flags = hdr->task_label_flags;
    if (task_label_flags & (DYNSEC_CACHE_DISABLE|DYNSEC_CACHE_CLEAR)) {
        task_label_flags = 0;
    } else if (task_label_flags & DYNSEC_CACHE_ENABLE) {
        task_label_flags &= (DYNSEC_CACHE_ENABLE
            | DYNSEC_CACHE_IGNORE
            | DYNSEC_CACHE_INHERIT
            | DYNSEC_CACHE_INHERIT_RECURSE
        );
    } else {
        return -EINVAL;
    }

    ret = -ENOENT;

    tid = hdr->tid;
    task = dynsec_get_next_task(DUMP_NEXT_THREAD, &tid);
    if (task) {
        if (task->pid == hdr->tid && task->tgid == hdr->pid) {
            // Call with task refcount held so we don't insert after
            // security_task_free
            ret = set_task_label_flags(hdr->tid, task_label_flags, GFP_KERNEL);
        }
        put_task_struct(task);
    }

    return ret;
}

// May only be called by clone/fork hooks.
// Duplicates and translates parent label if exits and inheritable.
int task_cache_insert_new_task(pid_t tid, pid_t parent_pid, bool is_thread,
                               gfp_t mode)
{
    u32 hash;
    unsigned long flags = 0;
    struct task_entry *entry, *old_entry;
    struct task_bkt *bkt;
    int bkt_index;
    struct task_key key = {};
    u32 task_label_flags = 0;
    int ret = -EEXIST;
    bool has_parent = false;

    if (!task_cache || !task_cache->enabled || !tid) {
        return -EINVAL;
    }

    has_parent = find_parent_task_labels(parent_pid, &task_label_flags);
    pr_debug("%s: %s %s:%d %s:%d %#x\n", __func__,
            has_parent ? "has_parent" : "parent not found",
                is_thread ? "tid" : "pid", tid,
                is_thread ? "pid" : "ppid", parent_pid,
                task_label_flags
    );
    if (has_parent && (task_label_flags & DYNSEC_CACHE_INHERIT)) {
        // Unset inheritability if not a thread.
        // Threads retain same label as main thread for simplicity.
        if (!is_thread &&
            !(task_label_flags & DYNSEC_CACHE_INHERIT_RECURSE)) {

            task_label_flags &= ~(DYNSEC_CACHE_INHERIT);
            pr_debug("%s: %s:%d dropping inherit from %s:%d: %#x\n",
                    __func__,
                    is_thread ? "tid" : "pid", tid,
                    is_thread ? "pid" : "ppid", parent_pid,
                    task_label_flags);
        } else {
            pr_debug("%s: %s:%d inheriting from %s:%d %#x\n",
                    __func__,
                    is_thread ? "tid" : "pid", tid,
                    is_thread ? "pid" : "ppid", parent_pid,
                    task_label_flags);
        }
    } else {
        if (has_parent && task_label_flags) {
            pr_debug("%s: %s:%d Not inheriting parent %s:%d label: %#x\n",
                    __func__,
                    is_thread ? "tid" : "pid", tid,
                    is_thread ? "pid" : "ppid", parent_pid,
                    task_label_flags);

            // Parent label was not inheritable. Insert later on as needed.
            return 0;
        }

        // Parent did not exist or had no label. Insert later as needed.
        return -ENOENT;
    }

    entry = kzalloc(sizeof(*entry), mode);
    if (!entry) {
        return -ENOMEM;
    }

    key.tid = tid;
    hash = task_hash(&key, task_cache->seed);
    entry->hash = hash;
    entry->hits = 1;
    memcpy(&entry->key, &key, sizeof(key));
    INIT_LIST_HEAD(&entry->list);

    entry->last.event_type = DYNSEC_EVENT_TYPE_MAX;
    entry->task_label_flags = task_label_flags;
    entry->last_stall.event_type = DYNSEC_EVENT_TYPE_MAX;

    bkt_index = task_bucket_index(hash);
    bkt = &(task_cache->bkt[bkt_index]);

    ret = -EEXIST;

    // Don't insert if someone beat us to it
    spin_lock_irqsave(&bkt->lock, flags);
    old_entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (!old_entry) {
        ret = 0;
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
        // Set to NULL to know insert worked
        entry = NULL;
    }
    spin_unlock_irqrestore(&bkt->lock, flags);

    // Free Entry if not inserted
    if (entry) {
        kfree(entry);
        entry = NULL;
    }

    pr_debug("%s: inserted tid:%d ret:%d\n", __func__, tid, ret);

    return ret;
}

int task_cache_set_last_event(pid_t tid, pid_t parent_pid, bool is_thread,
                              struct event_track *event,
                              struct event_track *prev_event, gfp_t mode)
{
    u32 hash;
    unsigned long flags = 0;
    struct task_entry *entry;
    struct task_bkt *bkt;
    int bkt_index;
    struct task_key key = {};
    u32 task_label_flags = 0;
    bool has_parent = false;

    if (!task_cache || !task_cache->enabled || !event || !tid) {
        return -EINVAL;
    }

    if (event->event_type < 0 ||
        event->event_type >= DYNSEC_EVENT_TYPE_TASK_DUMP) {
        return -ERANGE;
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

    has_parent = find_parent_task_labels(parent_pid, &task_label_flags);
    pr_debug("%s: %s %s:%d %s:%d %#x\n", __func__,
            has_parent ? "has_parent" : "parent not found",
            is_thread ? "tid" : "pid", tid,
            is_thread ? "pid" : "ppid", parent_pid,
            task_label_flags
    );
    if (has_parent && (task_label_flags & DYNSEC_CACHE_INHERIT)) {
        // Unset inheritability if not a thread
        if (!is_thread &&
            !(task_label_flags & DYNSEC_CACHE_INHERIT_RECURSE)) {
            task_label_flags &= ~(DYNSEC_CACHE_INHERIT);
            pr_debug("%s: %s:%d dropping inherit from %s:%d: %#x\n", __func__,
                    is_thread ? "tid" : "pid", tid,
                    is_thread ? "pid" : "ppid", parent_pid,
                    task_label_flags);
        } else {
            pr_debug("%s: %s:%d inheriting from %s:%d %#x\n", __func__,
                    is_thread ? "tid" : "pid", tid,
                    is_thread ? "pid" : "ppid", parent_pid,
                    task_label_flags);
        }

        // Simulate the __update_entry_data behavior of
        // adjusting the report_flags on the "new" event_track.
        if (task_label_flags & DYNSEC_CACHE_ENABLE) {
            if ((task_label_flags & DYNSEC_CACHE_IGNORE)) {
                event->report_flags &= ~(DYNSEC_REPORT_STALL);
                event->report_flags |= DYNSEC_REPORT_IGNORE;
                event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
            } else {
                event->report_flags &= ~(DYNSEC_REPORT_STALL);
                event->report_flags |= DYNSEC_REPORT_CACHED;
                event->track_flags |= TRACK_EVENT_REPORT_FLAGS_CHG;
            }
        }
    } else {
        task_label_flags = 0;
    }

    memcpy(&entry->last, event, sizeof(*event));
    entry->task_label_flags = task_label_flags;
    if (event->report_flags & DYNSEC_REPORT_STALL) {
        memcpy(&entry->last_stall, event, sizeof(*event));
    } else {
        entry->last_stall.event_type = DYNSEC_EVENT_TYPE_MAX;
    }

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
    u32 cache_flags = 0;
    u32 task_label_flags = 0;
    int ret = -ENOENT;
    bool has_ignore_opt = false;
    bool clear_events_opt = false;
    bool clear_task_opt = false;

    if (!task_cache || !task_cache->enabled || !response) {
        return -EINVAL;
    }
    if (response->event_type < 0 ||
        response->event_type >= DYNSEC_EVENT_TYPE_TASK_DUMP) {
        return -ERANGE;
    }

    // For now only allow task level or task-event level options.
    // If both are set, task level takes precedence.

    if (response->task_label_flags) {
        task_label_flags = response->task_label_flags;
        if (task_label_flags & (DYNSEC_CACHE_CLEAR|DYNSEC_CACHE_DISABLE)) {
            clear_task_opt = true;
            task_label_flags &= ~(DYNSEC_CACHE_CLEAR|DYNSEC_CACHE_DISABLE);
            if (task_label_flags) {
                return -EINVAL;
            }
        } else {
            task_label_flags &= (DYNSEC_CACHE_ENABLE
                | DYNSEC_CACHE_IGNORE
                | DYNSEC_CACHE_INHERIT
                | DYNSEC_CACHE_INHERIT_RECURSE
            );
            if (task_label_flags) {
                // No point in labeling if ENABLE is not set
                if (!(task_label_flags & DYNSEC_CACHE_ENABLE)) {
                    return -EINVAL;
                }

                // INHERIT_RECURSE option requires the INHERIT
                if (task_label_flags & DYNSEC_CACHE_INHERIT_RECURSE) {
                    if (!(task_label_flags & DYNSEC_CACHE_INHERIT)) {
                        return -EINVAL;
                    }
                }
            }
        }
    }

    else if (response->cache_flags) {
        cache_flags = response->cache_flags;

        // Exclude DYNSEC_CACHE_CLEAR from mask to allow
        // clearing before setting an option.
        // requests to clear everything before setting
        if (cache_flags & DYNSEC_CACHE_CLEAR) {
            clear_events_opt = true;
            cache_flags &= ~(DYNSEC_CACHE_CLEAR);
        }

        // DISABLE just wipes out current event type's label
        if (cache_flags & DYNSEC_CACHE_DISABLE) {
            cache_flags = DYNSEC_CACHE_DISABLE;
        }

        // Determine if any of the ENABLE events can be set
        else {
            // IGNORE opt requires another bit to be set
            // Allow setting this event if we are not in ignore mode
            if (cache_flags & DYNSEC_CACHE_IGNORE) {
                has_ignore_opt = true;
                cache_flags &= ~(DYNSEC_CACHE_IGNORE);
            }
            // One of these options must be set unless clear bit is set
            cache_flags &= (DYNSEC_CACHE_ENABLE |
                            DYNSEC_CACHE_ENABLE_EXCL |
                            DYNSEC_CACHE_ENABLE_STRICT |
                            DYNSEC_CACHE_CLEAR_ON_EVENT);

            // Only one of these can be set
            if (hweight32(cache_flags) == 1) {
                // Restore ignore opt
                if (has_ignore_opt) {
                    cache_flags |= DYNSEC_CACHE_IGNORE;
                }
            } else {
                // Only let this label request if clearing
                // to allow a default safe option.
                if (clear_events_opt) {
                    cache_flags = 0;
                    has_ignore_opt = false;
                }
                // Too many or lack of options set so 
                else {
                    return -EINVAL;
                }
            }

            // Ensure we override the task level options
            clear_task_opt = true;
            task_label_flags = 0;
        }
    } else {
        return 0;
    }

    pr_debug("%s: tid:%u task_label_flags:%#x\n", __func__,
            response->tid, task_label_flags);

    key.tid = response->tid;
    hash = task_hash(&key, task_cache->seed);
    bkt_index = task_bucket_index(hash);
    bkt = &(task_cache->bkt[bkt_index]);

    // Lookup Entry
    spin_lock_irqsave(&bkt->lock, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        ret = 0;

        if (clear_events_opt || task_label_flags) {
            memset(entry->event_caches, 0, sizeof(entry->event_caches));
        }

        if (clear_task_opt || task_label_flags) {
            entry->task_label_flags = task_label_flags;
        } else if (cache_flags) {
            // Set appropriate event level cache option
            if (cache_flags & DYNSEC_CACHE_DISABLE) {
                entry->event_caches[response->event_type] = 0;
            } else {
                entry->event_caches[response->event_type] = cache_flags;
            }
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

void task_cache_display_buckets(struct seq_file *m)
{
    unsigned long flags;
    u32 i, size;

    if (!task_cache || !task_cache->bkt) {
        return;
    }

    pr_debug("Display task cache non-zero bucket sizes\n");
    for (i = 0; i < TASK_BUCKETS; i++) {
        size = 0;
        spin_lock_irqsave(&task_cache->bkt[i].lock, flags);
        if (task_cache->bkt[i].size) {
            size = task_cache->bkt[i].size;
        }
        spin_unlock_irqrestore(&task_cache->bkt[i].lock, flags);
        if (size) {
            seq_printf(m, "TaskCache Bucket %06d: size: %d", i, size);
            seq_puts(m, "\n");
        }
    }
}
