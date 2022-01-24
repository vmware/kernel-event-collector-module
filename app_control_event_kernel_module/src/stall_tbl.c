// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/fs.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/version.h>

#include "stall_tbl.h"
#include "stall_reqs.h"
#include "factory.h"
#include "inode_cache.h"


#define STALL_BUCKET_BITS 12
#define STALL_BUCKETS BIT(STALL_BUCKET_BITS)

static u32 stall_hash(u32 secret, struct stall_key *key)
{
    return jhash(key, sizeof(*key), secret);
}
static int stall_bkt_index(u32 hash)
{
    return hash & (STALL_BUCKETS - 1);
}

static void stall_tbl_free_entries(struct stall_tbl *stall_tbl)
{

}

static inline unsigned long lock_stall_bkt(struct stall_bkt *bkt, unsigned long flags)
{
    spin_lock_irqsave(&bkt->lock, flags);
    return flags;
}

static inline void unlock_stall_bkt(struct stall_bkt *bkt, unsigned long flags)
{
    spin_unlock_irqrestore(&bkt->lock, flags);
}

static inline unsigned long lock_stall_queue(struct stall_q *queue, unsigned long flags)
{
    spin_lock_irqsave(&queue->lock, flags);
    return flags;
}

static inline void unlock_stall_queue(struct stall_q *queue, unsigned long flags)
{
    spin_unlock_irqrestore(&queue->lock, flags);
}

static void stall_queue_defer_wakeup(struct irq_work *work)
{
    struct stall_q *queue;

    queue = container_of(work, struct stall_q, defer_wakeup);
    wake_up_interruptible(&queue->wq);
}

static void stall_queue_wakeup(struct stall_q *queue, bool defer)
{
    if (waitqueue_active(&queue->wq)) {
        if (defer) {
            irq_work_queue(&queue->defer_wakeup);
        } else {
            wake_up(&queue->wq);
        }
    }
}

static void stall_queue_clear(struct stall_tbl *tbl)
{
    unsigned long flags = 0;
    struct dynsec_event *entry;
    struct dynsec_event *tmp;

    flags = lock_stall_queue(&tbl->queue, flags);
    list_for_each_entry_safe(entry, tmp, &tbl->queue.list, list) {
        list_del_init(&entry->list);
        free_dynsec_event(entry);
    }
    tbl->queue.size = 0;
    unlock_stall_queue(&tbl->queue, flags);
}

u32 stall_queue_size(struct stall_tbl *tbl)
{
    u32 size;
    unsigned long flags;

    if (!stall_tbl_enabled(tbl)) {
        return 0;
    }
    flags = lock_stall_queue(&tbl->queue, flags);
    size = tbl->queue.size;
    unlock_stall_queue(&tbl->queue, flags);
    return size;
}

struct dynsec_event *stall_queue_shift(struct stall_tbl *tbl, size_t space)
{
    unsigned long flags = 0;
    struct dynsec_event *event = NULL;
    uint16_t payload;

    if (!stall_tbl_enabled(tbl)) {
        return NULL;
    }

    // Check there is enough available space before dequeue
    flags = lock_stall_queue(&tbl->queue, flags);
    event = list_first_entry_or_null(&tbl->queue.list, struct dynsec_event, list);
    if (event) {
        payload = get_dynsec_event_payload(event);
        if (!payload || payload > space) {
            event = NULL;
        } else {
            list_del_init(&event->list);
            tbl->queue.size -= 1;
        }
    }
    unlock_stall_queue(&tbl->queue, flags);

    return event;
}

static void stall_tbl_wake_entries(struct stall_tbl *stall_tbl)
{
    unsigned long flags;
    struct stall_entry *entry;
    struct stall_entry *tmp;
    u32 i;

    for (i = 0; i < STALL_BUCKETS; i++) {
        flags = lock_stall_bkt(&stall_tbl->bkt[i], flags);
        list_for_each_entry_safe(entry, tmp, &stall_tbl->bkt[i].list,
                      list) {
            entry->mode = DYNSEC_STALL_MODE_DISABLE;
            spin_lock(&entry->lock);
            entry->response = DYNSEC_RESPONSE_ALLOW;
            spin_unlock(&entry->lock);

            wake_up(&entry->wq);
        }
        unlock_stall_bkt(&stall_tbl->bkt[i], flags);
    }
}

static struct stall_entry *lookup_entry_safe(u32 hash, struct stall_key *key,
                                             struct list_head *head)
{
    struct stall_entry *entry;
    struct stall_entry *tmp;

    list_for_each_entry_safe(entry, tmp, head, list) {
        if (entry->hash == hash &&
            entry->key.tid == key->tid &&
            entry->key.req_id == key->req_id &&
            entry->key.event_type == key->event_type) {
            return entry;
        }
    }
    return NULL;
}

#ifdef USE_SAFE_ENTRY_LOOKUP
// This lookup helper is helpful for debugging
static struct stall_entry *entry_in_list(struct stall_entry *target,
                                         struct list_head *head)
{
    struct stall_entry *entry;
    struct stall_entry *tmp;

    list_for_each_entry_safe(entry, tmp, head, list) {
        if (entry == target) {
            return entry;
        }
    }
    return NULL;
}
#endif /* USE_SAFE_ENTRY_LOOKUP */

struct stall_tbl *stall_tbl_alloc(gfp_t mode)
{
    u32 i;
    struct stall_tbl *tbl = kzalloc(sizeof(struct stall_tbl), mode);

    if (!tbl) {
        return NULL;
    }
    tbl->enabled = false;
    tbl->used_vmalloc = false;

    get_random_bytes(&tbl->secret, sizeof(tbl->secret));

    tbl->bkt =
        kcalloc(STALL_BUCKETS, sizeof(struct stall_bkt), mode);
    if (!tbl->bkt) {
        tbl->bkt = vmalloc(STALL_BUCKETS *
                           sizeof(struct stall_bkt));
        if (!tbl->bkt) {
            kfree(tbl);
            return NULL;
        }

        tbl->used_vmalloc = true;
        memset(tbl->bkt, 0,
               STALL_BUCKETS * sizeof(struct stall_bkt));
    }

    for (i = 0; i < STALL_BUCKETS; i++) {
        spin_lock_init(&tbl->bkt[i].lock);
        tbl->bkt[i].size = 0;
        INIT_LIST_HEAD(&tbl->bkt[i].list);
    }


    // event queue
    spin_lock_init(&tbl->queue.lock);
    tbl->queue.size = 0;
    INIT_LIST_HEAD(&tbl->queue.list);
    init_waitqueue_head(&tbl->queue.wq);
    init_waitqueue_head(&tbl->queue.pre_wq);
    init_irq_work(&tbl->queue.defer_wakeup, stall_queue_defer_wakeup);

    return tbl;
}

void stall_tbl_enable(struct stall_tbl *tbl)
{
    if (tbl) {
        tbl->enabled = true;
        tbl->tgid = current->tgid;
    }
}

void stall_tbl_disable(struct stall_tbl *tbl)
{
    if (tbl) {
        tbl->enabled = false;

        // Stalled tasks should take responsibility to free
        stall_tbl_wake_entries(tbl);

        stall_queue_clear(tbl);

        if (waitqueue_active(&tbl->queue.wq)) {
            irq_work_sync(&tbl->queue.defer_wakeup);
        }
    }
}

void stall_tbl_shutdown(struct stall_tbl *tbl)
{
    if (tbl) {
        // Shutdown Cache
        stall_tbl_disable(tbl);

        // Iterate through entries and free
        stall_tbl_free_entries(tbl);

        if (tbl->bkt) {
            if (tbl->used_vmalloc) {
                vfree(tbl->bkt);
            } else {
                kfree(tbl->bkt);
            }
            tbl->bkt = NULL;
        }
        kfree(tbl);
    }
}

static u32 stall_tbl_enqueue_event(struct stall_tbl *tbl, struct dynsec_event *event)
{
    u32 size = 0;

    if (!bypass_mode_enabled() &&
        stall_tbl_enabled(tbl) && event) {
        unsigned long flags = 0;

        flags = lock_stall_queue(&tbl->queue, flags);
        list_add_tail(&event->list, &tbl->queue.list);
        tbl->queue.size += 1;
        size = tbl->queue.size;
        unlock_stall_queue(&tbl->queue, flags);
    }

    return size;
}

u32 enqueue_nonstall_event(struct stall_tbl *tbl,
                           struct dynsec_event *event)
{
    u32 size = stall_tbl_enqueue_event(tbl, event);

    if (size) {
        if (meets_notify_threshold(size) ||
            !(event->report_flags & DYNSEC_REPORT_LO_PRI)) {

            // Optionally could defer wake ups but let's not
            // turn it on unless we have to.
            // stall_queue_wakeup(&tbl->queue, true);
            stall_queue_wakeup(&tbl->queue, false);
        }
    } else {
        free_dynsec_event(event);
    }

    return size;
}

u32 enqueue_nonstall_event_no_notify(struct stall_tbl *tbl,
                                     struct dynsec_event *event)
{
    u32 size = stall_tbl_enqueue_event(tbl, event);

    if (!size) {
        free_dynsec_event(event);
    }

    return size;
}

struct stall_entry *
stall_tbl_insert(struct stall_tbl *tbl, struct dynsec_event *event, gfp_t mode)
{
    struct stall_entry *entry;
    unsigned long flags;
    int index;

    if (!stall_tbl_enabled(tbl) || !event) {
        return ERR_PTR(-EINVAL);
    }

    entry = kzalloc(sizeof(*entry), mode);
    if (!entry) {
        return ERR_PTR(-ENOMEM);
    }

    INIT_LIST_HEAD(&entry->list);

    // Protect write-able fields
    spin_lock_init(&entry->lock);

    init_waitqueue_head(&entry->wq);

    // Copy event unique identifiers
    entry->key.req_id = event->req_id;
    entry->key.event_type = event->event_type;
    entry->key.tid = event->tid;

    // Copy over inode_addr data
    entry->inode_addr = event->inode_addr;

    // Build bucket lookup data
    entry->hash = stall_hash(tbl->secret, &entry->key);
    index = stall_bkt_index(entry->hash);

    getrawmonotonic(&entry->start);

    flags = lock_stall_bkt(&stall_tbl->bkt[index], flags);
    list_add(&entry->list, &tbl->bkt[index].list);
    tbl->bkt[index].size += 1;
    unlock_stall_bkt(&stall_tbl->bkt[index], flags);

    (void)stall_tbl_enqueue_event(tbl, event);

    stall_queue_wakeup(&tbl->queue, false);

    return entry;
}

int stall_tbl_resume(struct stall_tbl *tbl, struct stall_key *key,
                     int response, unsigned long inode_cache_flags)
{
    struct stall_entry *entry;
    unsigned long flags;
    int index;
    u32 hash;
    int ret = -ENOENT;
    unsigned long inode_addr = 0;

    if (!stall_tbl_enabled(tbl) || !key) {
        return -EINVAL;
    }

    if (key->event_type < 0 || key->event_type >= DYNSEC_EVENT_TYPE_MAX) {
        return -EINVAL;
    }

    switch (response)
    {
    case DYNSEC_RESPONSE_ALLOW:
        break;
    case DYNSEC_RESPONSE_EPERM:
        // Remove inode from read only cache if we deny
        inode_cache_flags = DYNSEC_CACHE_DISABLE;
        break;

    default:
        return -EINVAL;
    }

    // Should be called very selectively
    if (inode_cache_flags & DYNSEC_CACHE_CLEAR) {
        inode_cache_clear();
        inode_cache_flags &= ~(DYNSEC_CACHE_CLEAR);
    }

    // If inode cache flags are bad just don't do anything
    if (inode_cache_flags) {
        if (!(inode_cache_flags & (DYNSEC_CACHE_DISABLE|DYNSEC_CACHE_ENABLE))) {
            inode_cache_flags = DYNSEC_CACHE_DISABLE;
        }
    }

    hash = stall_hash(tbl->secret, key);
    index = stall_bkt_index(hash);
    // pr_info("%s:%d hash:%#x idx:%d req_id:%llu type:%x\n",
    //         __func__, __LINE__, hash, index, key->req_id,
    //         key->event_type);
    flags = lock_stall_bkt(&tbl->bkt[index], flags);
    entry = lookup_entry_safe(hash, key, &tbl->bkt[index].list);
    if (entry) {
        ret = 0;
        inode_addr = entry->inode_addr;

        entry->mode = DYNSEC_STALL_MODE_RESUME;
        // spin_lock(&entry->lock);
        entry->response = response;
        // spin_unlock(&entry->lock);
        if (waitqueue_active(&entry->wq)) {
            wake_up(&entry->wq);
        }
    }
    unlock_stall_bkt(&tbl->bkt[index], flags);

    if (inode_addr) {
        inode_cache_update(inode_addr, inode_cache_flags);
    }

    return ret;
}

int stall_tbl_remove_entry(struct stall_tbl *tbl, struct stall_entry *entry)
{
    unsigned long flags;
    int index;
    int ret = -ENOENT;

    if (!tbl || !entry) {
        return -EINVAL;
    }

    index = stall_bkt_index(entry->hash);
    flags = lock_stall_bkt(&tbl->bkt[index], flags);
#ifdef USE_SAFE_ENTRY_LOOKUP
    if (entry_in_list(entry, &tbl->bkt[index].list)) {
#endif /* USE_SAFE_ENTRY_LOOKUP */
        list_del_init(&entry->list);
        tbl->bkt[index].size += -1;
        ret = 0;
#ifdef USE_SAFE_ENTRY_LOOKUP
    }
#endif /* USE_SAFE_ENTRY_LOOKUP */
    unlock_stall_bkt(&tbl->bkt[index], flags);
    // pr_info("%s:%d ret:%d hash:%#x idx:%d req_id:%llu type:%x\n",
    //         __func__, __LINE__, ret, entry->hash, index, entry->key.req_id,
    //         entry->key.event_type);
    return ret;
}

int stall_tbl_remove_by_key(struct stall_tbl *tbl, struct stall_key *key)
{
    struct stall_entry *entry = NULL;
    unsigned long flags;
    u32 hash;
    int index;
    int ret = -ENOENT;

    if (!tbl || !key) {
        return -EINVAL;
    }

    hash = stall_hash(tbl->secret, key);
    index = stall_bkt_index(hash);
    flags = lock_stall_bkt(&tbl->bkt[index], flags);
    entry = lookup_entry_safe(hash, key, &tbl->bkt[index].list);
    if (entry) {
        list_del_init(&entry->list);
        tbl->bkt[index].size += -1;
        ret = 0;
    }
    unlock_stall_bkt(&tbl->bkt[index], flags);

    if (entry) {
        kfree(entry);
    }

    return ret;
}
