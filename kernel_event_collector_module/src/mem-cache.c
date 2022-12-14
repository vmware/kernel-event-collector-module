// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"

#include "mem-cache.h"
#include "mem-alloc.h"

#include "cb-spinlock.h"

extern bool g_enable_mem_cache_tracking __read_mostly;

static struct
{
    uint64_t          lock;
    struct list_head  list;
} s_mem_cache;

typedef struct cache_buffer {
    uint32_t  magic;
    struct list_head  list;
    CB_MEM_CACHE *cache;

    // This tracks the owners of this object
    atomic64_t refcnt;
    bool is_owned;
} cache_buffer_t;

#define CACHE_BUFFER_MAGIC   0xDEADBEEF
static const size_t CACHE_BUFFER_SZ = sizeof(cache_buffer_t);

#ifdef MEM_DEBUG
    struct list_head mem_debug_list = LIST_HEAD_INIT(mem_debug_list);

    void __ec_mem_cache_generic_report_leaks(void);
#endif

static inline void *__ec_get_valuep(const cache_buffer_t *cache_buffer)
{
    return (void *)((char *)cache_buffer + CACHE_BUFFER_SZ);
}
static inline cache_buffer_t *__ec_get_bufferp(const void *value)
{
    return (cache_buffer_t *)((char *)value - CACHE_BUFFER_SZ);
}

// Get the size of this string, and subtract the `\0`
#define MEM_CACHE_PREFIX_LEN   (sizeof(MEM_CACHE_PREFIX) - 1)

bool ec_mem_cache_init(ProcessContext *context)
{
    INIT_LIST_HEAD(&s_mem_cache.list);
    // ec_spinlock_init calls ec_mem_alloc, all initialization needs to happen before this call
    ec_spinlock_init(&s_mem_cache.lock, context);
    return true;
}

void ec_mem_cache_shutdown(ProcessContext *context)
{
    // cp_spinlock_destroy calls ec_mem_free, this must be called before other shutdown
    ec_spinlock_destroy(&s_mem_cache.lock, context);

    // TODO: Check cache list
}

bool ec_mem_cache_create(CB_MEM_CACHE *cache, const char *name, size_t size, ProcessContext *context)
{
    if (cache)
    {
        cache->object_size = size;
        // prefix the cache name with a unique prefix to avoid conflicts with cbr
        cache->name[0] = 0;
        strncat(cache->name, MEM_CACHE_PREFIX, CB_MEM_CACHE_NAME_LEN);
        strncat(cache->name, name, CB_MEM_CACHE_NAME_LEN - MEM_CACHE_PREFIX_LEN);
        INIT_LIST_HEAD(&cache->allocation_list);

        cache->kmem_cache = kmem_cache_create(
            cache->name,
            cache->object_size + CACHE_BUFFER_SZ,
            0,
            SLAB_HWCACHE_ALIGN,
            NULL);
        ec_percpu_counter_init(&cache->allocated_count, 0, GFP_MODE(context));


        if (likely(cache->kmem_cache))
        {
            ec_spinlock_init(&cache->lock, context);
            ec_write_lock(&s_mem_cache.lock, context);
            list_add(&cache->node, &s_mem_cache.list);
            ec_write_unlock(&s_mem_cache.lock, context);

            return true;
        }
    }
    return false;
}

uint64_t ec_mem_cache_destroy(CB_MEM_CACHE *cache, ProcessContext *context)
{
    uint64_t allocated_count = 0;

    if (likely(cache && cache->kmem_cache))
    {
        // cache->node only needs to be deleted from the list if cache->kmem_cache was allocated
        // otherwise it was never added to s_mem_cache.list and may have invalid next and prev pointers
        ec_write_lock(&s_mem_cache.lock, context);
        list_del_init(&cache->node);
        ec_write_unlock(&s_mem_cache.lock, context);

        allocated_count = percpu_counter_sum_positive(&cache->allocated_count);
        if (allocated_count > 0)
        {
            TRACE(DL_ERROR, "Destroying Memory Cache (%s) with %lld allocated items.",
                   cache->name, (unsigned long long)allocated_count);

            if (g_enable_mem_cache_tracking)
            {
                struct cache_buffer *cache_buffer = NULL;
                void *value = NULL;

                ec_write_lock(&cache->lock, context);
                list_for_each_entry(cache_buffer, &cache->allocation_list, list)
                {
                    if (likely(cache_buffer))
                    {
                        TRACE(DL_ERROR, "    CACHE %s (ref: %ld) (%p)",
                            cache->name,
                            atomic64_read(&cache_buffer->refcnt),
                            cache_buffer);
                        if (cache->printval_callback)
                        {
                            value = __ec_get_valuep(cache_buffer);
                            cache->printval_callback(value, context);
                        }
                    }
                }
                ec_write_unlock(&cache->lock, context);

            }
        }

        percpu_counter_destroy(&cache->allocated_count);
        ec_spinlock_destroy(&cache->lock, context);

        kmem_cache_destroy(cache->kmem_cache);
        cache->kmem_cache = NULL;
    }

    return allocated_count;
}

#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 3)
    // CB-10446
    // We observed a kernel panic in kmem_cache_alloc affecting only Centos/RHEL 7. This was
    //  found to be a documented "use after free" issue in the 3.10 kernel which is fixed in
    //  3.10.0-327.22.2.el7 (Late 7.2).  It appears that using GFP_ATOMIC for ALL kmem_cache_alloc calls
    //  seems to workaround the problem. Unfortunately there is no test for the specific version.
    //
    // http://lkml.iu.edu/hypermail/linux/kernel/1403.1/04340.html
    // https://patchwork.ozlabs.org/patch/303498/
    #define CHECK_GFP(CONTEXT)  CB_ATOMIC
#else
    #define CHECK_GFP(CONTEXT)  GFP_MODE(CONTEXT)
#endif

void *ec_mem_cache_alloc(CB_MEM_CACHE *cache, ProcessContext *context)
{
    void *value = NULL;

    if (likely(cache && cache->kmem_cache))
    {
        value = kmem_cache_alloc(cache->kmem_cache, CHECK_GFP(context));
        if (value)
        {
            cache_buffer_t *cache_buffer = (cache_buffer_t *)value;

            cache_buffer->magic = CACHE_BUFFER_MAGIC;
            cache_buffer->is_owned = true;

            // Init the refcount and take an initial reference
            atomic64_set(&cache_buffer->refcnt, 1);

            cache_buffer->cache = cache;
            percpu_counter_inc(&cache->allocated_count);
            if (g_enable_mem_cache_tracking)
            {
                ec_write_lock(&cache->lock, context);
                list_add(&cache_buffer->list, &cache->allocation_list);
                ec_write_unlock(&cache->lock, context);
            }

            value = __ec_get_valuep(cache_buffer);
        } else {
            TRACE(DL_ERROR, "kmem_cache_alloc failed, mode %s, pid: %d", IS_ATOMIC(context) ? "ATOMIC" : "KERNEL", context->pid);
        }
    }

    return value;
}

void ec_mem_cache_disown(void *value, ProcessContext *context)
{
    if (value)
    {
        cache_buffer_t *cache_buffer = __ec_get_bufferp(value);

        if (likely(cache_buffer->magic == CACHE_BUFFER_MAGIC))
        {
            cache_buffer->is_owned = false;
            ec_mem_cache_put(value, context);
        } else
        {
            TRACE(DL_ERROR, "Cache entry magic does not match.  Failed to disown memory: %p %x", value, cache_buffer->magic);
            CB_BUG();
        }
    }
}

bool ec_mem_cache_is_owned(void *value, ProcessContext *context)
{
    if (value)
    {
        cache_buffer_t *cache_buffer = __ec_get_bufferp(value);

        return cache_buffer->is_owned;
    }
    return false;
}

void __ec_mem_cache_release(cache_buffer_t *cache_buffer, ProcessContext *context)
{
    if (likely(cache_buffer && cache_buffer->cache))
    {
        CB_MEM_CACHE *cache = cache_buffer->cache;

        if (likely(cache_buffer->magic == CACHE_BUFFER_MAGIC))
        {
            if (cache->delete_callback)
            {
                void *value = __ec_get_valuep(cache_buffer);

                cache->delete_callback(value, context);
            }

            if (g_enable_mem_cache_tracking)
            {
                ec_write_lock(&cache->lock, context);
                list_del_init(&cache_buffer->list);
                ec_write_unlock(&cache->lock, context);
            }

            if (likely(cache_buffer->cache->kmem_cache))
            {
                kmem_cache_free(cache->kmem_cache, (void *)cache_buffer);
            } else
            {
                    TRACE(DL_ERROR, "Cache %s already destroyed.  Failed to free memory: %p",
                            cache_buffer->cache->name, cache_buffer);
                    dump_stack();
            }

            percpu_counter_dec(&cache->allocated_count);
        } else
        {
            TRACE(DL_ERROR, "Cache entry magic does not match.  Failed to free memory: %p %x", cache_buffer, cache_buffer->magic);
            CB_BUG();
        }
    }
}

void ec_mem_cache_get(void *value, ProcessContext *context)
{
    if (value)
    {
        cache_buffer_t *cache_buffer = __ec_get_bufferp(value);

        if (likely(cache_buffer->magic == CACHE_BUFFER_MAGIC))
        {
            atomic64_inc(&cache_buffer->refcnt);
        } else
        {
            TRACE(DL_ERROR, "%s: Cache entry magic does not match.  Failed to get memory: %p %x", __func__, value, cache_buffer->magic);
            CB_BUG();
        }
    }
}

void ec_mem_cache_put(void *value, ProcessContext *context)
{
    if (value)
    {
        cache_buffer_t *cache_buffer = __ec_get_bufferp(value);

        if (likely(cache_buffer->magic == CACHE_BUFFER_MAGIC))
        {
            IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(&cache_buffer->refcnt, {
                __ec_mem_cache_release(cache_buffer, context);
            });
        } else
        {
            TRACE(DL_ERROR, "%s: Cache entry magic does not match.  Failed to put memory: %p %x", __func__, value, cache_buffer->magic);
            CB_BUG();
        }
    }
}

int64_t ec_mem_cache_ref_count(void *value, ProcessContext *context)
{
    if (value)
    {
        cache_buffer_t *cache_buffer = __ec_get_bufferp(value);

        return atomic64_read(&cache_buffer->refcnt);
    }

    return 0;
}

int64_t ec_mem_cache_get_allocated_count(CB_MEM_CACHE *cache, ProcessContext *context)
{
    CANCEL(cache, 0);

    return percpu_counter_sum_positive(&cache->allocated_count);
}

size_t ec_mem_cache_get_memory_usage(ProcessContext *context)
{
    CB_MEM_CACHE *cache;
    size_t        size = 0;

    ec_write_lock(&s_mem_cache.lock, context);
    list_for_each_entry(cache, &s_mem_cache.list, node) {
            size += cache->object_size * percpu_counter_sum_positive(&cache->allocated_count);
    }
    ec_write_unlock(&s_mem_cache.lock, context);

    return size;
}

#define SUFFIX_LIST_SIZE  4
void __ec_simplify_size(int64_t *size, const char **suffix)
{
    int s_index = 0;
    static const char * const suffix_list[SUFFIX_LIST_SIZE] = { "bytes", "Kb", "Mb", "Gb" };

    CANCEL_VOID(size && suffix);

    while (*size > 1024 && s_index < (SUFFIX_LIST_SIZE - 1))
    {
        *size /= 1024;
        s_index++;
    }

    *suffix = suffix_list[s_index];
}

int ec_mem_cache_show(struct seq_file *m, void *v)
{
    CB_MEM_CACHE *cache;
    int64_t size = 0;
    int64_t simple_size = 0;
    const char *suffix;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    seq_printf(m, "%40s | %6s | %40s | %9s |\n",
                  "Name", "Alloc", "Cache Name", "Obj. Size");

    ec_write_lock(&s_mem_cache.lock, &context);
    list_for_each_entry(cache, &s_mem_cache.list, node) {
            const char *cache_name = cache->kmem_cache ? cache->kmem_cache->name : "";
            int         cache_size = cache->object_size;
            long        count      = percpu_counter_sum_positive(&cache->allocated_count);

            seq_printf(m, "%40s | %6ld | %40s | %9d |\n",
                       cache->name,
                       count,
                       cache_name,
                       cache_size);
            size += count * cache_size;
    }
    ec_write_unlock(&s_mem_cache.lock, &context);

    simple_size = size;
    __ec_simplify_size(&simple_size, &suffix);

    seq_puts(m, "\n");
    seq_printf(m, "Allocated Cache Memory         : %lld %s (%lld)\n", simple_size, suffix, size);

    size = ec_mem_allocated_size(&context);
    simple_size = size;
    __ec_simplify_size(&simple_size, &suffix);

    seq_printf(m, "Allocated Generic Memory       : %lld %s (%lld)\n", simple_size, suffix, size);
    seq_printf(m, "Allocated Generic Memory Count : %lld\n", ec_mem_allocated_count(&context));

    return 0;
}
