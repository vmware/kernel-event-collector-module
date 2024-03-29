// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "hash-table.h"
#include "cb-spinlock.h"
#include "mem-alloc.h"

typedef struct hash_table_node {
    struct list_head link;
    u32 hash;
    u32 activity;
    HashTbl *hashTblp;
} HashTableNode;

static const size_t HASH_NODE_SZ = sizeof(HashTableNode);

bool __ec_hashtbl_proc_initialize(HashTbl *hashTblp, ProcessContext *context);
void __ec_hashtbl_proc_shutdown(HashTbl *hashTblp, ProcessContext *context);
void __ec_hashtbl_cache_delete_cb(void *value, ProcessContext *context);
void __ec_hashtbl_print_callback(void *data, ProcessContext *context);

static inline void *__ec_get_datap(const HashTbl *hashTblp, HashTableNode *nodep)
{
    return (void *)((char *)nodep + HASH_NODE_SZ);
}
inline HashTableNode *__ec_get_nodep(const HashTbl *hashTblp, void *datap)
{
    return (HashTableNode *)((char *)datap - HASH_NODE_SZ);
}

static __read_mostly struct {
    uint64_t         lock;
    struct list_head list;
} s_hashtbl;

#define HASHTBL_PRINT(fmt, ...)    do { if (hashTblp->debug_logging) pr_err("hash-tbl: " fmt, ##__VA_ARGS__); } while (0)

char *__ec_key_in_hex(ProcessContext *context, unsigned char *key, int key_len)
{
    int i;
    char *str = (char *) ec_mem_alloc(key_len * 3, context);

    for (i = 0; i < key_len; i++)
    {
        sprintf(str + i*3, "%02x ", key[i]);
    }
    str[key_len * 3 - 1] = '\0';
    return str;
}

inline void *__ec_get_key_ptr(HashTbl *hashTblp, void *datap)
{
    return (void *) datap + hashTblp->key_offset;
}

bool ec_hashtbl_startup(ProcessContext *context)
{
    ec_spinlock_init(&s_hashtbl.lock, context);
    INIT_LIST_HEAD(&s_hashtbl.list);

    return true;
}

void ec_hashtbl_shutdown(ProcessContext *context)
{
    ec_spinlock_destroy(&s_hashtbl.lock, context);
}

static inline u32 ec_hashtbl_hash_key(HashTbl *hashTblp,
                   unsigned char *key)
{
    return jhash(key, hashTblp->key_len, hashTblp->secret);
}
static inline int ec_hashtbl_bkt_index(HashTbl *hashTblp, u32 hash)
{
    return hash & (hashTblp->numberOfBuckets - 1);
}

static void ec_hashtbl_bkt_read_lock(HashTableBkt *bkt, ProcessContext *context)
{
    ec_read_lock(&bkt->lock, context);
}
static void ec_hashtbl_bkt_read_unlock(HashTableBkt *bkt, ProcessContext *context)
{
    ec_read_unlock(&bkt->lock, context);
}

static void ec_hashtbl_bkt_write_lock(HashTableBkt *bkt, ProcessContext *context)
{
    ec_write_lock(&bkt->lock, context);
}
static void ec_hashtbl_bkt_write_unlock(HashTableBkt *bkt, ProcessContext *context)
{
    ec_write_unlock(&bkt->lock, context);
}

bool ec_hashtbl_init(
    HashTbl        *hashTblp,
    ProcessContext *context)
{
    unsigned int i;
    size_t tableSize;
    unsigned char *tbl_storage_p  = NULL;

    CANCEL_MSG(hashTblp, false, DL_ERROR, "%s: HashTbl NULL", __func__);
    CANCEL_MSG(!hashTblp->initialized, false, DL_ERROR, "%s: HashTbl already initialized", __func__);
    CANCEL_MSG(hashTblp->name != NULL
        && hashTblp->numberOfBuckets > 0
        && hashTblp->key_len > 0
        && hashTblp->datasize > 0,
        false, DL_ERROR, "%s: Bad data for init", __func__);

    if (unlikely(!is_power_of_2(hashTblp->numberOfBuckets)))
    {
        hashTblp->numberOfBuckets = roundup_pow_of_two(hashTblp->numberOfBuckets);
        TRACE(DL_ERROR, "%s: Increase bucket size to %llu", __func__, hashTblp->numberOfBuckets);
    }

    tableSize = hashTblp->numberOfBuckets * sizeof(HashTableBkt);

    //Since we're not in an atomic context this is an acceptable alternative to
    //kmalloc however, it should be noted that this is a little less efficient. The reason for this is
    //fragmentation that can occur on systems. We noticed this happening in the field, and if highly
    //fragmented, our driver will fail to load with a normal kmalloc
    tbl_storage_p  = ec_mem_valloc(tableSize, context);

    CANCEL_MSG(tbl_storage_p, NULL, DL_ERROR, "[%s:%d] Failed to allocate %luB at .",
        __func__, __LINE__, tableSize);

    //With kzalloc we get zeroing for free, with vmalloc we need to do it ourself
    memset(tbl_storage_p, 0, tableSize);

    HASHTBL_PRINT("Cache=%s elemsize=%llu\n", hashTblp->name, hashTblp->datasize);

    hashTblp->tablePtr = (HashTableBkt *)tbl_storage_p;
    hashTblp->base_size   = tableSize + sizeof(HashTbl);
    ec_percpu_counter_init(&hashTblp->tableInstance, 0, GFP_MODE(context));

    hashTblp->hash_cache.delete_callback = __ec_hashtbl_cache_delete_cb;
    if (hashTblp->printval_callback)
    {
        hashTblp->hash_cache.printval_callback = __ec_hashtbl_print_callback;
    }

    TRY_MSG(ec_mem_cache_create(&hashTblp->hash_cache, hashTblp->name, hashTblp->datasize + HASH_NODE_SZ, context),
        DL_ERROR, "%s: Failed to create memory cache", __func__);

    // Make hash more random
    get_random_bytes(&hashTblp->secret, sizeof(hashTblp->secret));

    for (i = 0; i < hashTblp->numberOfBuckets; i++)
    {
        ec_spinlock_init(&hashTblp->tablePtr[i].lock, context);
        INIT_LIST_HEAD(&hashTblp->tablePtr[i].head);
    }

    INIT_LIST_HEAD(&hashTblp->genTables);
    ec_write_lock(&s_hashtbl.lock, context);
    list_add(&(hashTblp->genTables), &s_hashtbl.list);
    ec_write_unlock(&s_hashtbl.lock, context);

    __ec_hashtbl_proc_initialize(hashTblp, context);

    HASHTBL_PRINT("Size=%lu NumberOfBuckets=%llu\n", tableSize, hashTblp->numberOfBuckets);
    HASHTBL_PRINT("ADDR=%p TADDR=%p OFFSET=%lu\n", hashTblp, hashTblp->tablePtr, sizeof(HashTbl));

    hashTblp->initialized = true;
    return true;

CATCH_DEFAULT:
    ec_mem_free(tbl_storage_p);
    percpu_counter_destroy(&hashTblp->tableInstance);
    hashTblp->tablePtr = NULL;
    return false;
}

int __ec_hashtbl_delete_callback(HashTbl *hashTblp, void *datap, void *priv, ProcessContext *context)
{
    return ACTION_DELETE;
}

void __ec_hashtbl_for_each(HashTbl *hashTblp, hashtbl_for_each_cb callback, void *priv, bool haveWriteLock, ProcessContext *context);

void ec_hashtbl_destroy(HashTbl *hashTblp, ProcessContext *context)
{
    unsigned int i;

    CANCEL_VOID(hashTblp && hashTblp->initialized);

    ec_write_lock(&s_hashtbl.lock, context);
    list_del_init(&(hashTblp->genTables));
    ec_write_unlock(&s_hashtbl.lock, context);

    hashTblp->initialized = false;

    __ec_hashtbl_proc_shutdown(hashTblp, context);

    __ec_hashtbl_for_each(hashTblp, __ec_hashtbl_delete_callback, NULL, true, context);

    HASHTBL_PRINT("hash shutdown inst=%" PRFs64 " alloc=%" PRFs64 "\n",
        percpu_counter_sum_positive(&hashTblp->tableInstance),
        ec_mem_cache_get_allocated_count(&hashTblp->hash_cache, context));

    for (i = 0; i < hashTblp->numberOfBuckets; i++)
    {
        ec_spinlock_destroy(&hashTblp->tablePtr[i].lock, context);
    }


    percpu_counter_destroy(&hashTblp->tableInstance);
    ec_mem_cache_destroy(&hashTblp->hash_cache, context);
    ec_mem_free(hashTblp->tablePtr);
}

void ec_hashtbl_clear(HashTbl *hashTblp, ProcessContext *context)
{
    HASHTBL_PRINT("ADDR=%p TADDR=%p OFFSET=%lu\n", hashTblp, hashTblp->tablePtr, sizeof(HashTbl));

    ec_hashtbl_write_for_each(hashTblp, __ec_hashtbl_delete_callback, NULL, context);
}

void ec_hashtbl_write_for_each(HashTbl *hashTblp, hashtbl_for_each_cb callback, void *priv, ProcessContext *context)
{
    CANCEL_VOID(hashTblp && hashTblp->initialized);

    __ec_hashtbl_for_each(hashTblp, callback, priv, true, context);
}

void ec_hashtbl_read_for_each(HashTbl *hashTblp, hashtbl_for_each_cb callback, void *priv, ProcessContext *context)
{
    CANCEL_VOID(hashTblp && hashTblp->initialized);

    __ec_hashtbl_for_each(hashTblp, callback, priv, false, context);
}

void __ec_hashtbl_for_each(HashTbl *hashTblp, hashtbl_for_each_cb callback, void *priv, bool haveWriteLock, ProcessContext *context)
{
    unsigned int i;
    uint64_t numberOfBuckets;
    HashTableBkt *ec_hashtbl_tbl  = NULL;

    if (!hashTblp) return;

    ec_hashtbl_tbl = hashTblp->tablePtr;
    numberOfBuckets  = hashTblp->numberOfBuckets;

    // May need to walk the lists too
    for (i = 0; i < numberOfBuckets; ++i)
    {
        HashTableBkt *bucketp = &ec_hashtbl_tbl[i];
        HashTableNode *nodep = 0, *next = 0;

        if (haveWriteLock)
        {
            ec_hashtbl_bkt_write_lock(bucketp, context);
        } else
        {
            ec_hashtbl_bkt_read_lock(bucketp, context);
        }

        if (!list_empty(&bucketp->head))
        {
            list_for_each_entry_safe(nodep, next, &bucketp->head, link)
            {

                switch ((*callback)(hashTblp, __ec_get_datap(hashTblp, nodep), priv, context))
                {
                case ACTION_DELETE:
                    // This should never be called with only a read lock
                    BUG_ON(!haveWriteLock);
                    list_del_init(&nodep->link);
                    --bucketp->itemCount;
                    percpu_counter_dec(&hashTblp->tableInstance);
                    ec_mem_cache_disown(nodep, context);
                    break;
                case ACTION_STOP:
                    if (haveWriteLock)
                    {
                        ec_hashtbl_bkt_write_unlock(bucketp, context);
                    } else
                    {
                        ec_hashtbl_bkt_read_unlock(bucketp, context);
                    }
                    goto Exit;
                    break;
                case ACTION_PRINT:
                    TRACE(DL_INFO, "bucket: %u, active: %u", i, nodep->activity);
                    break;
                case ACTION_CONTINUE:
                default:
                    break;
                }
            }
        }

        if (haveWriteLock)
        {
            ec_hashtbl_bkt_write_unlock(bucketp, context);
        } else
        {
            ec_hashtbl_bkt_read_unlock(bucketp, context);
        }
    }

Exit:
    // Signal the callback we are done.  It may need to clean up something in the context
    (*callback)(hashTblp, NULL, priv, context);
    return;
}

#define LRU_REORDERLIMIT 10

HashTableNode *__ec_hashtbl_lookup(HashTbl *hashTblp, struct list_head *head, u32 hash, const void *key)
{
    HashTableNode *tableNode = NULL;
    HashTableNode *nextNode = NULL;
    HashTableNode *prevNode = NULL;

    list_for_each_entry_safe(tableNode, nextNode, head, link)
    {
        if (hash == tableNode->hash &&
            memcmp(key, __ec_get_key_ptr(hashTblp, __ec_get_datap(hashTblp, tableNode)), hashTblp->key_len) == 0)
        {
            // 1. The cache entry's activity counter is incremented
            // 2. The previous (higher ranking) entry's activity counter is decremented
            // 3. If the difference between the two activity counters is geater than
            //    LRU_REORDERLIMIT the two entries are swapped
            tableNode->activity += 1;
            if (prevNode)
            {
                if (prevNode->activity > 0)
                {
                    prevNode->activity -= 1;
                }
                if (tableNode->activity > prevNode->activity &&
                    tableNode->activity - prevNode->activity > LRU_REORDERLIMIT)
                {
                    list_del_init(&tableNode->link);
                    list_add_tail(&tableNode->link, &prevNode->link);
                }
            }
            return tableNode;
        }
        prevNode = tableNode;
    }

    return NULL;
}

int __ec_hashtbl_add(HashTbl *hashTblp, void *datap, bool forceUnique, ProcessContext *context)
{
    uint64_t bucket_indx;
    HashTableBkt *bucketp = NULL;
    HashTableNode *nodep;
    char *key_str;
    void *key;
    int ret = 0;

    CANCEL(hashTblp && datap, -EINVAL);
    CANCEL(hashTblp->initialized, -EINVAL);

    nodep = __ec_get_nodep(hashTblp, datap);
    key = __ec_get_key_ptr(hashTblp, datap);
    nodep->hash = ec_hashtbl_hash_key(hashTblp, key);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, nodep->hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    if (hashTblp->debug_logging)
    {
        key_str = __ec_key_in_hex(context, key, hashTblp->key_len);
        HASHTBL_PRINT("%s: bucket=%llu key=%s\n", __func__, bucket_indx, key_str);
        ec_mem_free(key_str);
    }

    ec_hashtbl_bkt_write_lock(bucketp, context);

    if (hashTblp->lruSize > 0 && bucketp->itemCount >= hashTblp->lruSize)
    {
        // Evict from the LRU
        //  Note this happens before we enforce uniqueness, which may result in evicting an item without adding a new item.

        // If there are nodes in this bucket then evict one.
        HashTableNode *tableNode = list_last_entry(&bucketp->head, HashTableNode, link);
        void          *datap     = __ec_get_datap(hashTblp, tableNode);

        ec_hashtbl_del_lockheld(hashTblp, bucketp, datap, context);
    }

    if (forceUnique)
    {
        HashTableNode *old_node = __ec_hashtbl_lookup(hashTblp, &bucketp->head, nodep->hash, key);

        TRY_DO(!old_node, { ret = -EEXIST; });
    }

    list_add(&nodep->link, &bucketp->head);
    ++bucketp->itemCount;
    percpu_counter_inc(&hashTblp->tableInstance);
    ec_mem_cache_get(nodep, context);

CATCH_DEFAULT:
    ec_hashtbl_bkt_write_unlock(bucketp, context);

    return ret;
}

int ec_hashtbl_add(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    return __ec_hashtbl_add(hashTblp, datap, false, context);
}

int ec_hashtbl_add_safe(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    return __ec_hashtbl_add(hashTblp, datap, true, context);
}

void *ec_hashtbl_find(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    u32 hash;
    uint64_t bucket_indx;
    HashTableBkt *bucketp;
    HashTableNode *nodep = NULL;
    char *key_str;
    void *datap = NULL;

    if (!hashTblp || !key)
    {
        return NULL;
    }

    CANCEL(hashTblp->initialized, NULL);

    hash = ec_hashtbl_hash_key(hashTblp, key);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    if (hashTblp->debug_logging)
    {
        key_str = __ec_key_in_hex(context, key, hashTblp->key_len);
        HASHTBL_PRINT("%s: bucket=%llu key=%s\n", __func__, bucket_indx, key_str);
        ec_mem_free(key_str);
    }

    ec_hashtbl_bkt_read_lock(bucketp, context);
    nodep = __ec_hashtbl_lookup(hashTblp, &bucketp->head, hash, key);
    if (nodep && hashTblp->find_verify_callback)
    {
        if (!hashTblp->find_verify_callback(
                __ec_get_datap(hashTblp, nodep),
                key,
                context))
        {
            // If we failed the verify then reject this node
            nodep = NULL;
        }
    }
    if (nodep)
    {
        datap = ec_hashtbl_get(
            hashTblp,
            __ec_get_datap(hashTblp, nodep),
            context);
    }
    ec_hashtbl_bkt_read_unlock(bucketp, context);

    return datap;
}

void *ec_hashtbl_get(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    CANCEL(hashTblp && datap, NULL);

    ec_mem_cache_get(__ec_get_nodep(hashTblp, datap), context);
    if (hashTblp->handle_callback)
    {
        void *handle = hashTblp->handle_callback(datap, context);

        if (!handle)
        {
            // If we failed to get a handle, we want to release the reference and return NULL
            ec_hashtbl_put(hashTblp, datap, context);
        }

        // We want to return the handle
        datap = handle;
    }

    return datap;
}

int64_t ec_hashtbl_ref_count(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    CANCEL(hashTblp && datap, -1);

    return ec_mem_cache_ref_count(__ec_get_nodep(hashTblp, datap), context);
}

void ec_hashtbl_cache_ref_str(HashTbl *hashTblp, void *datap, char *buffer, size_t size, ProcessContext *context)
{
    CANCEL_VOID(likely(hashTblp && datap && buffer));

    snprintf(buffer, size, "%s ref:%lld",
        ec_mem_cache_is_owned(__ec_get_nodep(hashTblp, datap), context) ? "owned" : "not owned",
        ec_mem_cache_ref_count(__ec_get_nodep(hashTblp, datap), context));
    buffer[size] = 0;
}

int ec_hashtbl_del_lockheld(HashTbl *hashTblp, HashTableBkt *bucketp, void *datap, ProcessContext *context)
{
    HashTableNode *nodep = __ec_get_nodep(hashTblp, datap);

    // This protects against ec_hashtbl_del being called twice for the same datap
    if (!list_empty(&nodep->link))
    {
        list_del_init(&nodep->link);
        --bucketp->itemCount;
        percpu_counter_dec(&hashTblp->tableInstance);

        ec_mem_cache_disown(nodep, context);

        return 0;
    } else
    {
        // This can happen if an entry is evicted from the hashtbl while the datap is held by another thread
        // which then deletes it.
        TRACE(DL_INFO, "Attempt to delete a removed object from the hash table");
    }

    return -1;
}

void *ec_hashtbl_del_by_key(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    u32 hash;
    uint64_t bucket_indx;
    HashTableBkt *bucketp;
    HashTableNode *nodep = NULL;
    void *datap = NULL;

    if (!hashTblp || !key)
    {
        return NULL;
    }

    CANCEL(hashTblp->initialized, NULL);

    hash = ec_hashtbl_hash_key(hashTblp, key);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    ec_hashtbl_bkt_write_lock(bucketp, context);
    nodep = __ec_hashtbl_lookup(hashTblp, &bucketp->head, hash, key);
    if (nodep)
    {
        datap = __ec_get_datap(hashTblp, nodep);

        // We need to keep a lock for when we return
        ec_mem_cache_get(nodep, context);

        ec_hashtbl_del_lockheld(hashTblp, bucketp, datap, context);
    }
    ec_hashtbl_bkt_write_unlock(bucketp, context);

    // caller must put or free (if no reference count)
    return datap;
}

void ec_hashtbl_del(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    uint64_t bucket_indx;
    HashTableBkt *bucketp;
    HashTableNode *nodep;

    CANCEL_VOID(hashTblp != NULL);
    CANCEL_VOID(datap != NULL);
    CANCEL_VOID(hashTblp && hashTblp->initialized);

    nodep = __ec_get_nodep(hashTblp, datap);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, nodep->hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    ec_hashtbl_bkt_write_lock(bucketp, context);
    ec_hashtbl_del_lockheld(hashTblp, bucketp, datap, context);
    ec_hashtbl_bkt_write_unlock(bucketp, context);
}

int64_t ec_hashtbl_get_count(HashTbl *hashTblp, ProcessContext *context)
{
    CANCEL(hashTblp, 0);

    return percpu_counter_sum_positive(&hashTblp->tableInstance);
}

void *ec_hashtbl_alloc(HashTbl *hashTblp, ProcessContext *context)
{
    HashTableNode *nodep;

    CANCEL(hashTblp != NULL, NULL);
    CANCEL(hashTblp->initialized, NULL);

    nodep = (HashTableNode *)ec_mem_cache_alloc(&hashTblp->hash_cache, context);
    CANCEL(nodep, NULL);

    nodep->activity = 0;
    nodep->hash = 0;
    nodep->hashTblp = hashTblp;
    INIT_LIST_HEAD(&nodep->link);
    return __ec_get_datap(hashTblp, nodep);
}

void ec_hashtbl_put(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    CANCEL_VOID(likely(hashTblp != NULL));
    CANCEL_VOID(datap != NULL);

    ec_mem_cache_put(__ec_get_nodep(hashTblp, datap), context);
}

void ec_hashtbl_free(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    CANCEL_VOID(likely(hashTblp && datap));

    ec_mem_cache_disown(__ec_get_nodep(hashTblp, datap), context);
}

void __ec_hashtbl_cache_delete_cb(void *value, ProcessContext *context)
{
    HashTableNode *nodep = (HashTableNode *)value;

    if (likely(nodep))
    {
        HashTbl *hashTblp = nodep->hashTblp;

        if (hashTblp->delete_callback)
        {
            hashTblp->delete_callback(__ec_get_datap(hashTblp, nodep), context);
        }
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define CACHE_SIZE(a)      a->object_size
#else
#define CACHE_SIZE(a)      a->buffer_size
#endif

// Loop over each hash table and calculate the memory used
size_t ec_hashtbl_get_memory(ProcessContext *context)
{
    HashTbl *hashTblp;
    size_t   size = 0;

    ec_read_lock(&s_hashtbl.lock, context);
    list_for_each_entry(hashTblp, &s_hashtbl.list, genTables) {
            size += hashTblp->base_size;
    }
    ec_read_unlock(&s_hashtbl.lock, context);

    return size;
}

bool __ec_hashtbl_bkt_lock(bool haveWriteLock, HashTbl *hashTblp, void *key, void **datap, HashTableBkt **bkt, ProcessContext *context)
{
    u32 hash;
    uint64_t bucket_indx;
    HashTableBkt *bucketp;
    HashTableNode *nodep;

    if (!hashTblp || !key || !datap || !bkt)
    {
        return false;
    }

    CANCEL(hashTblp->initialized, NULL);

    hash = ec_hashtbl_hash_key(hashTblp, key);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    if (haveWriteLock)
    {
        ec_hashtbl_bkt_write_lock(bucketp, context);
    } else
    {
        ec_hashtbl_bkt_read_lock(bucketp, context);
    }

    nodep = __ec_hashtbl_lookup(hashTblp, &bucketp->head, hash, key);
    if (!nodep)
    {
        if (haveWriteLock)
        {
            ec_hashtbl_bkt_write_unlock(bucketp, context);
        } else
        {
            ec_hashtbl_bkt_read_unlock(bucketp, context);
        }
        return false;
    }

    *datap = __ec_get_datap(hashTblp, nodep);
    *bkt = bucketp;
    return true;
}

bool ec_hashtbl_read_bkt_lock(HashTbl *hashTblp, void *key, void **datap, HashTableBkt **bkt, ProcessContext *context)
{
    return __ec_hashtbl_bkt_lock(false, hashTblp, key, datap, bkt, context);
}

void ec_hashtbl_read_bkt_unlock(HashTableBkt *bkt, ProcessContext *context)
{
    if (bkt)
    {
        ec_hashtbl_bkt_read_unlock(bkt, context);
    }
}

bool ec_hashtbl_write_bkt_lock(HashTbl *hashTblp, void *key, void **datap, HashTableBkt **bkt, ProcessContext *context)
{
    return __ec_hashtbl_bkt_lock(true, hashTblp, key, datap, bkt, context);
}

void ec_hashtbl_write_bkt_unlock(HashTableBkt *bkt, ProcessContext *context)
{
    if (bkt)
    {
        ec_hashtbl_bkt_write_unlock(bkt, context);
    }
}

HashTableBkt *__ec_hashtbl_find_bucket(HashTbl *hashTblp, void *key)
{
    u32 hash;
    uint64_t bucket_indx;

    if (!hashTblp || !key)
    {
        return NULL;
    }

    CANCEL(hashTblp->initialized, NULL);

    hash = ec_hashtbl_hash_key(hashTblp, key);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, hash);

    return &(hashTblp->tablePtr[bucket_indx]);
}

void ec_hashtbl_read_lock(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    HashTableBkt *bucketp = __ec_hashtbl_find_bucket(hashTblp, key);

    if (bucketp)
    {
        ec_hashtbl_bkt_read_lock(bucketp, context);
    }
}

void ec_hashtbl_read_unlock(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    HashTableBkt *bucketp = __ec_hashtbl_find_bucket(hashTblp, key);

    if (bucketp)
    {
        ec_hashtbl_bkt_read_unlock(bucketp, context);
    }
}

void ec_hashtbl_write_lock(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    HashTableBkt *bucketp = __ec_hashtbl_find_bucket(hashTblp, key);

    if (bucketp)
    {
        ec_hashtbl_bkt_write_lock(bucketp, context);
    }
}

void ec_hashtbl_write_unlock(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    HashTableBkt *bucketp = __ec_hashtbl_find_bucket(hashTblp, key);

    if (bucketp)
    {
        ec_hashtbl_bkt_write_unlock(bucketp, context);
    }
}

struct counter {
    uint64_t itemCount;
    uint64_t bucketCount;
};

typedef void (*print_func)(void *, const char *, ...);

void ec_hastable_bkt_show(HashTbl *hashTblp, hastable_print_func _print, void *m, ProcessContext *context)
{
    int bucket_index = 0;
    int output_size = 0;
    struct counter *items = ec_mem_valloc(sizeof(struct counter) * hashTblp->numberOfBuckets, context);

    memset(items, 0, ec_mem_size(items));

    for (; bucket_index < hashTblp->numberOfBuckets; ++bucket_index)
    {
        int write_index = 0;
        uint64_t itemCount = hashTblp->tablePtr[bucket_index].itemCount;

        ec_read_lock(&hashTblp->tablePtr[bucket_index].lock, context);
        for (; write_index < output_size; ++write_index)
        {
            if (itemCount == items[write_index].itemCount)
            {
                break;
            } else if (itemCount < items[write_index].itemCount)
            {
                int i = output_size;

                for (; i > write_index; --i)
                {
                    int k = i - 1;

                    items[i] = items[k];
                    items[k].bucketCount = 0;
                }
                break;
            }
        }
        ec_read_unlock(&hashTblp->tablePtr[bucket_index].lock, context);
        if (items[write_index].bucketCount++ == 0)
        {
            items[write_index].itemCount = itemCount;
            ++output_size;
        }
    }

    _print(m, "%20s : %20s\n", "Bucket Depth", "Total Buckets");
    for (bucket_index = 0; bucket_index < output_size; ++bucket_index)
    {
        _print(m, "%20llu : %20llu\n", items[bucket_index].itemCount, items[bucket_index].bucketCount);
    }

    ec_mem_free(items);
}

int __ec_hashtbl_show(struct seq_file *m, void *v)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    HashTbl *hashTblp = (HashTbl *)m->private;

    seq_printf(m, "%20s : %20s\n", "Name", hashTblp->name);
    seq_printf(m, "%20s : %20llu\n", "Bucket Count", hashTblp->numberOfBuckets);
    seq_printf(m, "%20s : %20zu\n", "Table Size", hashTblp->base_size);
    seq_printf(m, "%20s : %20llu\n", "LRU Size", hashTblp->lruSize);
    seq_printf(m, "%20s : %20lld\n", "Item Count", percpu_counter_sum_positive(&hashTblp->tableInstance));
    seq_puts(m, "\n");

    ec_hastable_bkt_show(hashTblp, (hastable_print_func)seq_printf, m, &context);

    return 0;
}

int __ec_hashtbl_open(struct inode *inode, struct file *file)
{
    return single_open(file, __ec_hashtbl_show, PDE_DATA(inode));
}

static const struct file_operations ec_fops = {
    .owner      = THIS_MODULE,
    .open       = __ec_hashtbl_open,
    .read       = seq_read,
    .release    = single_release,
};

bool __ec_hashtbl_proc_initialize(HashTbl *hashTblp, ProcessContext *context)
{
    CANCEL(hashTblp, false);

    if (!proc_create_data(hashTblp->name, 0400, g_cb_hashtbl_proc_dir, &ec_fops, hashTblp))
    {
        TRACE(DL_ERROR, "Failed to create proc directory entry %s", hashTblp->name);
    }

    return true;
}

void __ec_hashtbl_proc_shutdown(HashTbl *hashTblp, ProcessContext *context)
{
    CANCEL_VOID(hashTblp);

    remove_proc_entry(hashTblp->name, g_cb_hashtbl_proc_dir);
}

void __ec_hashtbl_print_callback(void *data, ProcessContext *context)
{
    HashTableNode *nodep = (HashTableNode *)data;

    if (nodep && nodep->hashTblp && nodep->hashTblp->printval_callback)
    {
        nodep->hashTblp->printval_callback(__ec_get_datap(nodep->hashTblp, nodep), context);
    }
}

