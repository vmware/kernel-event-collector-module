// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"

#include "mem-cache.h"
#include "mem-alloc.h"

#include "cb-spinlock.h"

static struct
{
    uint64_t          lock;
    struct list_head  list;
} s_mem_cache;

typedef struct cache_buffer {
    uint32_t  magic;
    struct list_head  list;
} cache_buffer_t;

#define CACHE_BUFFER_MAGIC   0xDEADBEEF
static const size_t CACHE_BUFFER_SZ = sizeof(cache_buffer_t);

#ifdef MEM_DEBUG
    struct list_head mem_debug_list = LIST_HEAD_INIT(mem_debug_list);

    void __ec_mem_cache_generic_report_leaks(void);
#endif

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
            size + CACHE_BUFFER_SZ,
            0,
            SLAB_HWCACHE_ALIGN,
            NULL);
        ec_percpu_counter_init(&cache->allocated_count, 0, GFP_MODE(context));
        cache->object_size = size;


        if (cache->kmem_cache)
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

void ec_mem_cache_destroy(CB_MEM_CACHE *cache, ProcessContext *context, memcache_printval_cb printval_callback)
{
    void *value = NULL;
    struct cache_buffer *cb = NULL;

    if (cache && cache->kmem_cache)
    {
        uint64_t allocated_count = percpu_counter_sum_positive(&cache->allocated_count);

        // cache->node only needs to be deleted from the list if cache->kmem_cache was allocated
        // otherwise it was never added to s_mem_cache.list and may have invalid next and prev pointers
        ec_write_lock(&s_mem_cache.lock, context);
        list_del_init(&cache->node);
        ec_write_unlock(&s_mem_cache.lock, context);

        if (allocated_count > 0)
        {
            TRACE(DL_ERROR, "Destroying Memory Cache (%s) with %" PRFu64 " allocated items.",
                   cache->name, (unsigned long long)allocated_count);

            if (printval_callback)
            {
                ec_write_lock(&cache->lock, context);
                list_for_each_entry(cb, &cache->allocation_list, list)
                {
                    if (cb)
                    {
                        value = (char *)cb + CACHE_BUFFER_SZ;
                        printval_callback(value, context);
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

    if (cache && cache->kmem_cache)
    {
        value = kmem_cache_alloc(cache->kmem_cache, CHECK_GFP(context));
        if (value)
        {
            cache_buffer_t *cache_buffer = (cache_buffer_t *)value;

            cache_buffer->magic = CACHE_BUFFER_MAGIC;

            ec_write_lock(&cache->lock, context);
            list_add(&cache_buffer->list, &cache->allocation_list);
            ec_write_unlock(&cache->lock, context);

            percpu_counter_inc(&cache->allocated_count);

            value = (char *)cache_buffer + CACHE_BUFFER_SZ;
        }
    }

    return value;
}

void ec_mem_cache_free(CB_MEM_CACHE *cache, void *value, ProcessContext *context)
{
    if (value && cache->kmem_cache)
    {
        cache_buffer_t *cache_buffer = (cache_buffer_t *)((char *)value - CACHE_BUFFER_SZ);

        if (cache_buffer->magic == CACHE_BUFFER_MAGIC)
        {
            ec_write_lock(&cache->lock, context);
            list_del(&cache_buffer->list);
            ec_write_unlock(&cache->lock, context);

            kmem_cache_free(cache->kmem_cache, (void *)cache_buffer);
            percpu_counter_dec(&cache->allocated_count);
        } else
        {
            TRACE(DL_ERROR, "Cache entry magic does not match for %s.  Failed to free memory: %p", cache->name, value);
            dump_stack();
        }
    }
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
    const char *suffix;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    seq_printf(m, "%40s | %6s | %40s | %9s |\n",
                  "Name", "Alloc", "Cache Name", "Obj. Size");

    ec_write_lock(&s_mem_cache.lock, &context);
    list_for_each_entry(cache, &s_mem_cache.list, node) {
            const char *cache_name = cache->name;
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

    __ec_simplify_size(&size, &suffix);

    seq_puts(m, "\n");
    seq_printf(m, "Allocated Cache Memory         : %lld %s\n", size, suffix);

    size = ec_mem_allocated_size(&context);
    __ec_simplify_size(&size, &suffix);

    seq_printf(m, "Allocated Generic Memory       : %lld %s\n", size, suffix);
    seq_printf(m, "Allocated Generic Memory Count : %" PRFs64 "\n", ec_mem_allocated_count(&context));

    return 0;
}
