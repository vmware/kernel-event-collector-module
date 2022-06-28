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
#include "inode_cache.h"
#include "dynsec.h"

// Provide simple inode struct tracking for read-only use.

struct inode_bkt {
    spinlock_t lock;
    u32 size;
    struct list_head list;
};

struct inode_key {
    unsigned long inode_addr;
};

struct inode_entry {
    u32 hash;
    struct inode_key key;
    struct list_head list;
    u64 hits;
};

struct inode_cache {
    bool enabled;
    bool used_vmalloc;
    struct inode_bkt *bkt;
    u32 seed;
};

#define INODE_MAX_BKT_SZ 8
#define INODE_BUCKET_BITS 14
#define INODE_BUCKETS BIT(INODE_BUCKET_BITS)

static struct inode_cache *inode_cache = NULL;

static inline u32 inode_hash(struct inode_key *key, u32 secret)
{
    return jhash(key, sizeof(*key), secret);
}
static int inode_bucket_index(u32 hash)
{
    return hash & (INODE_BUCKETS - 1);
}
static inline unsigned long lock_bucket(struct inode_bkt *bkt, unsigned long flags)
{
    spin_lock_irqsave(&bkt->lock, flags);
    return flags;
}
static inline void unlock_bucket(struct inode_bkt *bkt, unsigned long flags)
{
    spin_unlock_irqrestore(&bkt->lock, flags);
}

static void inode_cache_free_entries(void)
{
    struct inode_entry *entry, *tmp;
    int i;
    unsigned long flags;
    u32 total_entries = 0;
    u32 bkts_used = 0;

    if (!inode_cache || !inode_cache->bkt) {
        return;
    }

    for (i = 0; i < INODE_BUCKETS; i++) {
        u32 size = 0;

        flags = lock_bucket(&inode_cache->bkt[i], flags);
        size = inode_cache->bkt[i].size;
        list_for_each_entry_safe (entry, tmp, &inode_cache->bkt[i].list,
                      list) {
            list_del_init(&entry->list);
            kfree(entry);
        }
        inode_cache->bkt[i].size = 0;
        unlock_bucket(&inode_cache->bkt[i], flags);

        total_entries += size;
        if (size) {
            bkts_used += 1;
        }
    }
    if (total_entries) {
        pr_info("inode hashtbl: total entries:%u bkts_used:%u\n",
                total_entries, bkts_used);
    }
}

int inode_cache_register(void)
{
    u32 i;

    inode_cache = kzalloc(sizeof(struct inode_cache), GFP_KERNEL);
    if (!inode_cache) {
        return -ENOMEM;
    }

    inode_cache->bkt =
        kcalloc(INODE_BUCKETS, sizeof(struct inode_bkt), GFP_KERNEL);
    if (inode_cache->bkt) {
        inode_cache->used_vmalloc = false;
    } else {
        inode_cache->bkt = vmalloc(INODE_BUCKETS * sizeof(struct inode_bkt));
        if (!inode_cache->bkt) {
            kfree(inode_cache);
            inode_cache = NULL;
            return -ENOMEM;
        }
        inode_cache->used_vmalloc = true;
        memset(inode_cache->bkt, 0,
               INODE_BUCKETS * sizeof(struct inode_bkt));
    }

    for (i = 0; i < INODE_BUCKETS; i++) {
        spin_lock_init(&inode_cache->bkt[i].lock);
        inode_cache->bkt[i].size = 0;
        INIT_LIST_HEAD(&inode_cache->bkt[i].list);
        cond_resched();
    }

    get_random_bytes(&inode_cache->seed, sizeof(inode_cache->seed));

    inode_cache->enabled = 1;
    return 0;
}

void inode_cache_clear(void)
{
    inode_cache_free_entries();
}

void inode_cache_disable(void)
{
    if (inode_cache && inode_cache->enabled) {
        inode_cache_clear();
        inode_cache->enabled = false;
    }
}

void inode_cache_enable(void)
{
    if (inode_cache && inode_cache->bkt) {
        inode_cache->enabled = true;
    }
}

void inode_cache_shutdown(void)
{
    if (inode_cache) {
        // Shutdown Cache
        inode_cache->enabled = false;
        inode_cache_free_entries();

        // Iterate through entries and free
        if (inode_cache->bkt) {
            if (inode_cache->used_vmalloc) {
                vfree(inode_cache->bkt);
            } else {
                kfree(inode_cache->bkt);
            }
            inode_cache->bkt = NULL;
        }

        kfree(inode_cache);
        inode_cache = NULL;
    }
}

static struct inode_entry *__lookup_entry_safe(u32 hash, struct inode_key *key,
                                              struct list_head *head)
{
    struct inode_entry *entry;
    struct inode_entry *tmp;
    list_for_each_entry_safe(entry, tmp, head, list) {
        if (entry->hash == hash &&
            entry->key.inode_addr == key->inode_addr) {
            return entry;
        }
    }
    return NULL;
}

#define is_entry_disabled(entry) (entry->hits <= 0)

int inode_cache_lookup(unsigned long inode_addr, u64 *hits,
                       bool insert, gfp_t mode)
{
    u32 hash;
    unsigned long flags = 0;
    struct inode_entry *entry;
    struct inode_bkt *bkt;
    int bkt_index;
    struct inode_key key = {};
    struct inode_entry *new_entry = NULL;
    struct inode_entry *free_me = NULL;
    int ret = -ENOENT;

    if (!inode_cache || !inode_cache->enabled || !inode_addr) {
        return -EINVAL;
    }

    if (hits) {
        *hits = 0;
    }

    key.inode_addr = inode_addr;
    hash = inode_hash(&key, inode_cache->seed);
    bkt_index = inode_bucket_index(hash);
    bkt = &(inode_cache->bkt[bkt_index]);

    // PreAllocate new entry
    if (insert) {
        new_entry = kzalloc(sizeof(*new_entry), mode);
        if (new_entry) {
            new_entry->hash = hash;
            INIT_LIST_HEAD(&new_entry->list);
            memcpy(&new_entry->key, &key, sizeof(new_entry->key));
        }
    }

    // Lookup Entry
    flags = lock_bucket(bkt, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        ret = 0;
        if (!is_entry_disabled(entry)) {
            entry->hits += 1;
        }
        if (hits) {
            *hits = entry->hits;
        }
        // Free preallocated entry after lock
        free_me = new_entry;
    } else if (insert) {
        if (new_entry) {
            if (bkt->size >= INODE_MAX_BKT_SZ) {
                // Remove oldest entry as needed
                free_me = list_entry(bkt->list.prev, struct inode_entry, list);
                list_del_init(&free_me->list);
                list_add(&new_entry->list, &bkt->list);
            } else {
                list_add(&new_entry->list, &bkt->list);
                bkt->size += 1;
            }
        }
        // Only return -ENOMEM if needed preallocated entry
        else {
            ret = -ENOMEM;
        }
    }
    unlock_bucket(bkt, flags);

    kfree(free_me);

    return ret;
}

int inode_cache_update(unsigned long inode_addr,
                       unsigned long cache_flags)
{
    u32 hash;
    unsigned long flags = 0;
    struct inode_entry *entry;
    struct inode_entry *free_me = NULL;
    struct inode_bkt *bkt;
    int bkt_index;
    struct inode_key key = {};
    int ret = -ENOENT;

    if (!inode_cache || !inode_cache->enabled || !inode_addr) {
        return -EINVAL;
    }

    cache_flags &= (DYNSEC_CACHE_ENABLE|DYNSEC_CACHE_DISABLE);

    key.inode_addr = inode_addr;
    hash = inode_hash(&key, inode_cache->seed);
    bkt_index = inode_bucket_index(hash);
    bkt = &(inode_cache->bkt[bkt_index]);

    // Lookup Entry
    flags = lock_bucket(bkt, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        // Either mark as disabled via zero hits
        // or increment hits.
        if (cache_flags & DYNSEC_CACHE_ENABLE) {
            entry->hits += 1;
        }
        else {
            free_me = entry;
            list_del_init(&entry->list);
            bkt->size -= 1;
        }
        ret = 0;
    }
    unlock_bucket(bkt, flags);

    if (free_me) {
        kfree(free_me);
    }

    return ret;
}

void inode_cache_remove_entry(unsigned long inode_addr)
{
    u32 hash;
    unsigned long flags = 0;
    struct inode_entry *entry;
    struct inode_bkt *bkt;
    int bkt_index;
    struct inode_key key = {
        .inode_addr = (unsigned long)inode_addr,
    };

    if (!inode_cache || !inode_cache->enabled || !inode_addr) {
        return;
    }

    hash = inode_hash(&key, inode_cache->seed);
    bkt_index = inode_bucket_index(hash);
    bkt = &(inode_cache->bkt[bkt_index]);

    flags = lock_bucket(bkt, flags);
    entry = __lookup_entry_safe(hash, &key, &bkt->list);
    if (entry) {
        list_del_init(&entry->list);
        bkt->size -= 1;
    }
    unlock_bucket(bkt, flags);

    if (entry) {
        kfree(entry);
    }
}
