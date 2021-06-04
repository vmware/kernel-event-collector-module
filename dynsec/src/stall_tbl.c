// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/fs.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/wait.h>

#include "stall_tbl.h"
#include "stall_reqs.h"
#include "stall.h"


#define STALL_BUCKET_BITS 14
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
    // struct stall_entry *entry, *tmp;
    // int i;
    // unsigned long flags;

    // for (i = 0; i < STALL_BUCKETS; i++) {
    //     spin_lock_irqsave(&stall_tbl->bkt[i].lock, flags);
    //     list_for_each_entry_safe(entry, tmp, &stall_tbl->bkt[i].list,
    //                   list) {
    //         list_del_init(&entry->list);
    //         kfree(entry);
    //     }
    //     stall_tbl->bkt[i].size = 0;
    //     spin_unlock_irqrestore(&stall_tbl->bkt[i].lock, flags);
    // }
}

static void stall_queue_clear(struct stall_tbl *tbl)
{
    unsigned long flags;
    struct dynsec_event *entry;
    struct dynsec_event *tmp;

    spin_lock_irqsave(&tbl->queue.lock, flags);
    list_for_each_entry_safe(entry, tmp, &tbl->queue.list, list) {
        list_del_init(&entry->list);
        free_dynsec_event(entry);
    }
    tbl->queue.size = 0;
    spin_unlock_irqrestore(&tbl->queue.lock, flags);
}

u32 stall_queue_size(struct stall_tbl *tbl)
{
    u32 size;
    unsigned long flags;

    if (!stall_tbl_enabled(tbl)) {
        return 0;
    }
    spin_lock_irqsave(&tbl->queue.lock, flags);
    size = tbl->queue.size;
    spin_unlock_irqrestore(&tbl->queue.lock, flags);
    return size;
}

struct dynsec_event *stall_queue_shift(struct stall_tbl *tbl, size_t space)
{
    unsigned long flags;
    struct dynsec_event *event = NULL;
    uint16_t payload;

    if (!stall_tbl_enabled(tbl)) {
        return NULL;
    }

    // Check there is enough available space before dequeue
    spin_lock_irqsave(&tbl->queue.lock, flags);
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
    spin_unlock_irqrestore(&tbl->queue.lock, flags);

    return event;
}

static void stall_tbl_wake_entries(struct stall_tbl *stall_tbl)
{
    unsigned long flags;
    struct stall_entry *entry;
    struct stall_entry *tmp;
    u32 i;

    for (i = 0; i < STALL_BUCKETS; i++) {
        spin_lock_irqsave(&stall_tbl->bkt[i].lock, flags);
        list_for_each_entry_safe(entry, tmp, &stall_tbl->bkt[i].list,
                      list) {
            entry->mode = DYNSEC_STALL_MODE_DISABLE;
            spin_lock(&entry->lock);
            entry->response = DYNSEC_RESPONSE_ALLOW;
            spin_unlock(&entry->lock);

            wake_up(&entry->wq);
        }
        spin_unlock_irqrestore(&stall_tbl->bkt[i].lock, flags);
    }
}

static struct stall_entry *lookup_entry_safe(u32 hash, struct stall_key *key,
                                             struct list_head *head)
{
    struct stall_entry *entry;
    struct stall_entry *tmp;

    list_for_each_entry_safe(entry, tmp, head, list) {
        if (entry->hash == hash &&
            entry->key.req_id == key->req_id &&
            entry->key.event_type == key->event_type) {
            return entry;
        }
    }
    return NULL;
}

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

struct stall_tbl *stall_tbl_alloc(gfp_t mode)
{
    u32 i;
    struct stall_tbl *tbl = kzalloc(sizeof(struct stall_tbl), mode);

    if (!tbl) {
        return NULL;
    }
    tbl->enabled = false;

    get_random_bytes(&tbl->secret, sizeof(tbl->secret));

    tbl->bkt =
        kcalloc(STALL_BUCKETS, sizeof(struct stall_bkt), mode);
    if (!tbl->bkt) {
        kfree(tbl);
        return NULL;
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
    }
}

void stall_tbl_shutdown(struct stall_tbl *tbl)
{
    if (tbl) {
        // Shutdown Cache
        stall_tbl_disable(tbl);

        // Iterate through entries and free
        stall_tbl_free_entries(tbl);

        kfree(tbl);
    }
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

    // Build bucket lookup data
    entry->hash = stall_hash(tbl->secret, &entry->key);
    index = stall_bkt_index(entry->hash);

    getrawmonotonic(&entry->start);

    spin_lock_irqsave(&tbl->bkt[index].lock, flags);
    list_add(&entry->list, &tbl->bkt[index].list);
    tbl->bkt[index].size += 1;
    spin_unlock_irqrestore(&tbl->bkt[index].lock, flags);

    spin_lock_irqsave(&tbl->queue.lock, flags);
    list_add_tail(&event->list, &tbl->queue.list);
    tbl->queue.size += 1;
    spin_unlock_irqrestore(&tbl->queue.lock, flags);
    wake_up(&tbl->queue.wq);

    return entry;
}

int stall_tbl_resume(struct stall_tbl *tbl, struct stall_key *key, int response)
{
    struct stall_entry *entry;
    unsigned long flags;
    int index;
    u32 hash;
    int ret = -ENOENT;

    if (!stall_tbl_enabled(tbl) || !key) {
        pr_info("%s:%d\n", __func__, __LINE__);
        return -EINVAL;
    }

    switch (response)
    {
    case DYNSEC_RESPONSE_ALLOW:
    case DYNSEC_RESPONSE_EPERM:
        break;

    default:
        pr_info("%s:%d\n", __func__, __LINE__);
        return -EINVAL;
    }

    hash = stall_hash(tbl->secret, key);
    index = stall_bkt_index(hash);
    // pr_info("%s:%d hash:%#x idx:%d req_id:%llu type:%x\n",
    //         __func__, __LINE__, hash, index, key->req_id,
    //         key->event_type);
    spin_lock_irqsave(&tbl->bkt[index].lock, flags);
    entry = lookup_entry_safe(hash, key, &tbl->bkt[index].list);
    if (entry) {
        ret = 0;
        entry->mode = DYNSEC_STALL_MODE_RESUME;
        spin_lock(&entry->lock);
        entry->response = response;
        spin_unlock(&entry->lock);

        wake_up(&entry->wq);
    }
    spin_unlock_irqrestore(&tbl->bkt[index].lock, flags);
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
    spin_lock_irqsave(&tbl->bkt[index].lock, flags);
    if (entry_in_list(entry, &tbl->bkt[index].list)) {
        list_del_init(&entry->list);
        tbl->bkt[index].size += -1;
        ret = 0;
    }
    spin_unlock_irqrestore(&tbl->bkt[index].lock, flags);
    // pr_info("%s:%d ret:%d hash:%#x idx:%d req_id:%llu type:%x\n",
    //         __func__, __LINE__, ret, entry->hash, index, entry->key.req_id,
    //         entry->key.event_type);
    return ret;
}

int stall_tbl_remove_by_key(struct stall_tbl *tbl, struct stall_key *key)
{
    struct stall_entry *entry;
    unsigned long flags;
    u32 hash;
    int index;
    int ret = -ENOENT;

    if (!tbl || !key) {
        return -EINVAL;
    }

    hash = stall_hash(tbl->secret, key);
    index = stall_bkt_index(hash);
    spin_lock_irqsave(&tbl->bkt[index].lock, flags);
    entry = lookup_entry_safe(hash, key, &tbl->bkt[index].list);
    if (entry) {
        list_del_init(&entry->list);
        tbl->bkt[index].size += -1;
        ret = 0;
    }
    spin_unlock_irqrestore(&tbl->bkt[index].lock, flags);

    return ret;
}
