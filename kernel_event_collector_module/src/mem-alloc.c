// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 VMware Inc.  All rights reserved.

#include <linux/slab.h>
#include <linux/delay.h>

#include "mem-alloc.h"
#include "percpu-util.h"
#include "cb-test.h"
#include "task-helper.h"

void __ec_mem_release_callback(struct percpu_ref *ref);

static struct
{
    struct percpu_counter generic_buffer_count;
    struct percpu_counter waiting_for_dealloc;
    int64_t __percpu *generic_buffer_size;
} s_mem_alloc;

bool ec_mem_init(ProcessContext *context)
{
    ec_percpu_counter_init(&s_mem_alloc.generic_buffer_count, 0, GFP_MODE(context));
    ec_percpu_counter_init(&s_mem_alloc.waiting_for_dealloc, 0, GFP_MODE(context));
    s_mem_alloc.generic_buffer_size = ec_alloc_percpu(int64_t, GFP_MODE(context));

    TRY_MSG(s_mem_alloc.generic_buffer_size, DL_ERROR, "%s: Error allocating memory", __func__);

    return true;

CATCH_DEFAULT:
    percpu_counter_destroy(&s_mem_alloc.generic_buffer_count);
    percpu_counter_destroy(&s_mem_alloc.waiting_for_dealloc);
    return false;
}

void ec_mem_shutdown(ProcessContext *context)
{
    uint64_t waiting_for_dealloc = 0;
    int waiting_for_dealloc_attemts = 0;
    const int print_every_attempts = 100;
    int64_t generic_buffer_count;

    // The deallocation can happen in a workqueue, so we need to loop here until we know we are not waiting for any
    //  obects to complete.  Otherwise we will destroy the cache and possibly cause a crash when the workqueue runs
    waiting_for_dealloc = percpu_counter_sum_positive(&s_mem_alloc.waiting_for_dealloc);
    while (waiting_for_dealloc > 0)
    {
        if ((waiting_for_dealloc_attemts++ % print_every_attempts) == 0)
        {
            TRACE(DL_WARNING, "Wating for %lld refcount objects to dealloc", waiting_for_dealloc);
        }
        usleep_range(1000, 10000);
        waiting_for_dealloc = percpu_counter_sum_positive(&s_mem_alloc.waiting_for_dealloc);
    }*

    generic_buffer_count = percpu_counter_sum_positive(&s_mem_alloc.generic_buffer_count);
    if (generic_buffer_count != 0)
    {
        TRACE(DL_ERROR, "Exiting with %lld allocated objects (total size: %lld)",
            (long long)generic_buffer_count, ec_mem_allocated_size(context));
    }

    percpu_counter_destroy(&s_mem_alloc.generic_buffer_count);
    percpu_counter_destroy(&s_mem_alloc.waiting_for_dealloc);
    free_percpu(s_mem_alloc.generic_buffer_size);
    s_mem_alloc.generic_buffer_size = NULL;

    #ifdef MEM_DEBUG
        __ec_mem_cache_generic_report_leaks();
    #endif
}

int64_t ec_mem_allocated_count(ProcessContext *context)
{
    return percpu_counter_sum_positive(&s_mem_alloc.generic_buffer_count);
}

int64_t ec_mem_allocated_size(ProcessContext *context)
{
    int cpu;
    int64_t ret = 0;

    for_each_online_cpu(cpu) {
        int64_t *pcount = per_cpu_ptr(s_mem_alloc.generic_buffer_size, cpu);

        ret += *pcount;
    }

    return ret;
}

// Generic Memory Allocations
//  This is a wrapper aroud kmalloc and vmalloc that keeps track of the number and
//   size of allocations.
//
//  This logic will add overhead of a single `generic_buffer_t` instance to every
//   memory allocation to help decrement the allocation counter on free.
//
// We include the total allocation in the used memory reporte to user space.  We
//  also report the total `leaked` memory when the module is disabled.
typedef struct generic_buffer {
    uint32_t          magic;
    size_t            size;
    bool              isVirtual;
    struct percpu_ref refcnt;
    bool              is_owned;
    #ifdef MEM_DEBUG
    #define ALLOC_SOURCE_LEN 50
    char              alloc_source[ALLOC_SOURCE_LEN+1];
    struct list_head  list;
    #endif
} generic_buffer_t;

inline generic_buffer_t *__ec_get_buffer_t(const void *value)
{
    return (generic_buffer_t *)((char *)value - sizeof(generic_buffer_t));
}

#ifdef MEM_DEBUG
    #define MEM_DEBUG_ADD_ENTRY(BUFFER, CONTEXT, FN, LINE) \
        do {\
            snprintf((BUFFER)->alloc_source, ALLOC_SOURCE_LEN, "%s:%d", (FN), (LINE));\
            (BUFFER)->alloc_source[ALLOC_SOURCE_LEN] = 0;\
            list_add(&(BUFFER)->list, &mem_debug_list);\
        } while (0)


    #define MEM_DEBUG_DEL_ENTRY(BUFFER, FN, LINE) \
        do {\
            BUFFER->magic = 0;\
            list_del(&(BUFFER)->list);\
        } while (0)

#else

    #define MEM_DEBUG_ADD_ENTRY(BUFFER, CONTEXT, FN, LINE)
    #define MEM_DEBUG_DEL_ENTRY(BUFFER, FN, LINE)

#endif

#define GENERIC_BUFFER_MAGIC   0xDEADBEEF
static const size_t GENERIC_BUFFER_SZ = sizeof(generic_buffer_t);

void *__ec_mem_alloc(const size_t size, ProcessContext *context, bool doVirtualAlloc, const char *fn, uint32_t line)
{
    void    *new_allocation = NULL;
    size_t   real_size      = size + GENERIC_BUFFER_SZ;

    // Ensure that we are passed valid size (greater than 0 and does not overflow)
    if (size > 0 && size < real_size)
    {
        if (!doVirtualAlloc)
        {
            new_allocation = kmalloc(real_size, GFP_MODE(context));
        } else if (doVirtualAlloc && IS_NON_ATOMIC(context))
        {
            new_allocation = vmalloc(real_size);
        } else
        {
            TRACE(DL_ERROR, "Generic MEM alloc failed: ATOMIC not allowed for vmalloc");
            return NULL;
        }

        if (new_allocation)
        {
            generic_buffer_t *generic_buffer = (generic_buffer_t *)new_allocation;

            generic_buffer->magic     = GENERIC_BUFFER_MAGIC;
            generic_buffer->size      = real_size;
            generic_buffer->isVirtual = doVirtualAlloc;
            generic_buffer->is_owned  = true;

            // Init reference count
            TRY(!ec_percpu_ref_init(&generic_buffer->refcnt, __ec_mem_release_callback, 0, GFP_MODE(context)));
            percpu_ref_get(&generic_buffer->refcnt);

            percpu_counter_inc(&s_mem_alloc.generic_buffer_count);
            this_cpu_add(*s_mem_alloc.generic_buffer_size, real_size);

            new_allocation = (char *)generic_buffer + sizeof(generic_buffer_t);

            MEM_DEBUG_ADD_ENTRY(generic_buffer, context, fn, line);
        }
    }

CATCH_DEFAULT:
    return new_allocation;
}

void __ec_mem_release_callback(struct percpu_ref *ref)
{
    // This is called from the percpu refcount release and may be in an atomic context
    //DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    if (likely(ref))
    {
        generic_buffer_t *generic_buffer = container_of(ref, generic_buffer_t, refcnt);

        percpu_counter_dec(&s_mem_alloc.generic_buffer_count);
        this_cpu_add(*s_mem_alloc.generic_buffer_size, generic_buffer->size * -1);
        MEM_DEBUG_DEL_ENTRY(generic_buffer, NULL, 0);
        percpu_ref_exit(&generic_buffer->refcnt);

        if (!generic_buffer->isVirtual)
        {
            kfree(generic_buffer);
        } else
        {
            vfree(generic_buffer);
        }
    }
}

void __ec_mem_kill_confirm_callback(struct percpu_ref *ref)
{
    percpu_counter_dec(&s_mem_alloc.waiting_for_dealloc);
}

void *ec_mem_get(void *value, ProcessContext *context)
{
    generic_buffer_t *generic_buffer = __ec_get_buffer_t(value);

    CANCEL(value, 0);

    if (likely(generic_buffer->magic == GENERIC_BUFFER_MAGIC))
    {
        percpu_ref_get(&generic_buffer->refcnt);
    } else
    {
        value = 0;
        TRACE(DL_ERROR, "Generic MEM cache magic does not match.  Failed to get memory: %p", value);
        dump_stack();
    }
    return value;
}

void __ec_mem_put(void *value, const char *fn, uint32_t line)
{
    generic_buffer_t *generic_buffer = __ec_get_buffer_t(value);

    CANCEL_VOID(value);

    if (likely(generic_buffer->magic == GENERIC_BUFFER_MAGIC))
    {
        percpu_ref_put(&generic_buffer->refcnt);
    } else
    {
        TRACE(DL_ERROR, "Magic does not match.  Failed to put memory: %p", value);
        dump_stack();
    }
}

void __ec_mem_disown(void *value, const char *fn, uint32_t line)
{
    generic_buffer_t *generic_buffer = __ec_get_buffer_t(value);

    CANCEL_VOID(value);

    if (likely(generic_buffer->magic == GENERIC_BUFFER_MAGIC))
    {
        if (likely(generic_buffer->is_owned))
        {
            generic_buffer->is_owned = false;
            percpu_counter_inc(&s_mem_alloc.waiting_for_dealloc);

            // Release the reference we are holding
            percpu_ref_put(&generic_buffer->refcnt);
            percpu_ref_kill_and_confirm(&generic_buffer->refcnt, __ec_mem_kill_confirm_callback);
        } else
        {
            TRACE(DL_ERROR, "Attempt to disown memory twice: %p", value);
            dump_stack();
        }
    } else
    {
        TRACE(DL_ERROR, "Magic does not match.  Failed to dissown memory: %p", value);
        dump_stack();
    }
}

size_t ec_mem_size(const void *value)
{
    size_t size = 0;
    generic_buffer_t *generic_buffer = __ec_get_buffer_t(value);

    CANCEL(value, 0);

    if (likely(generic_buffer->magic == GENERIC_BUFFER_MAGIC))
    {
        size = generic_buffer->size - GENERIC_BUFFER_SZ;
    } else
    {
        TRACE(DL_ERROR, "Generic MEM cache magic does not match.  Failed to check memory: %p", value);
        dump_stack();
    }
    return size;
}

char *ec_mem_strdup(const char *src, ProcessContext *context)
{
    return ec_mem_strdup_x(src, NULL, context);
}

char *ec_mem_strdup_x(const char *src, size_t *size, ProcessContext *context)
{
    char *dest = NULL;

    if (src)
    {
        size_t len = strlen(src);

        dest = ec_mem_alloc(len + 1, context);
        if (dest)
        {
            dest[0] = 0;
            strncat(dest, src, len);

            if (size)
            {
                *size = len + 1;
            }
        }
    }
    return dest;
}

#ifdef MEM_DEBUG
void __ec_mem_cache_generic_report_leaks(void)
{
    generic_buffer_t *generic_buffer;

    // We can't lock here because it has been destroyed
    list_for_each_entry(generic_buffer, &mem_debug_list, list)
    {
        TRACE(DL_ERROR, "## Buffer size=%ld, from %s", generic_buffer->size, generic_buffer->alloc_source);
    }
}
#endif
