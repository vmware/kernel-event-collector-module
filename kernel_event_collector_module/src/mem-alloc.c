// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 VMware Inc.  All rights reserved.

#include <linux/slab.h>

#include "mem-alloc.h"
#include "percpu-util.h"
#include "cb-test.h"

char *__ec_mem_strdup(const char *src, size_t size_in, ProcessContext *context);

static struct
{
    struct percpu_counter generic_buffer_count;
    int64_t __percpu *generic_buffer_size;
} s_mem_alloc;

bool ec_mem_init(ProcessContext *context)
{
    ec_percpu_counter_init(&s_mem_alloc.generic_buffer_count, 0, GFP_MODE(context));
    s_mem_alloc.generic_buffer_size = ec_alloc_percpu(int64_t, GFP_MODE(context));

    TRY_MSG(s_mem_alloc.generic_buffer_size, DL_ERROR, "%s: Error allocating memory", __func__);

    return true;

CATCH_DEFAULT:
    percpu_counter_destroy(&s_mem_alloc.generic_buffer_count);
    return false;
}

void ec_mem_shutdown(ProcessContext *context)
{
    int64_t generic_buffer_count;

    generic_buffer_count = percpu_counter_sum_positive(&s_mem_alloc.generic_buffer_count);

    if (generic_buffer_count != 0)
    {
        TRACE(DL_ERROR, "Exiting with %lld allocated objects (total size: %lld)",
            (long long)generic_buffer_count, ec_mem_allocated_size(context));
    }

    percpu_counter_destroy(&s_mem_alloc.generic_buffer_count);
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
    atomic64_t        ref_count;
    #ifdef MEM_DEBUG
    #define ALLOC_SOURCE_LEN 50
    char              alloc_source[ALLOC_SOURCE_LEN+1];
    struct list_head  list;
    #endif
} generic_buffer_t;

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
            if (!new_allocation)
            {
                TRACE(DL_ERROR, "kmalloc failed, mode %s, pid: %d", IS_ATOMIC(context) ? "ATOMIC" : "KERNEL", context->pid);
            }
        } else if (doVirtualAlloc && IS_NON_ATOMIC(context))
        {
            new_allocation = vmalloc(real_size);

            if (!new_allocation)
            {
                TRACE(DL_ERROR, "vmalloc failed, mode %s, pid: %d", IS_ATOMIC(context) ? "ATOMIC" : "KERNEL", context->pid);
            }
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
            percpu_counter_inc(&s_mem_alloc.generic_buffer_count);
            this_cpu_add(*s_mem_alloc.generic_buffer_size, real_size);

            // Init reference count
            atomic64_set(&generic_buffer->ref_count, 1);

            new_allocation = (char *)generic_buffer + sizeof(generic_buffer_t);

            MEM_DEBUG_ADD_ENTRY(generic_buffer, context, fn, line);
        }
    }

    return new_allocation;
}

void __ec_mem_free(void *value, const char *fn, uint32_t line)
{
    if (value)
    {
        generic_buffer_t *generic_buffer = (generic_buffer_t *)((char *)value - sizeof(generic_buffer_t));

        if (generic_buffer->magic == GENERIC_BUFFER_MAGIC)
        {
            IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(&generic_buffer->ref_count,
            {
                percpu_counter_dec(&s_mem_alloc.generic_buffer_count);
                this_cpu_sub(*s_mem_alloc.generic_buffer_size, generic_buffer->size);
                MEM_DEBUG_DEL_ENTRY(generic_buffer, fn, line);
                if (!generic_buffer->isVirtual)
                {
                    kfree(generic_buffer);
                } else
                {
                    vfree(generic_buffer);
                }
            });
        } else
        {
            TRACE(DL_ERROR, "Generic MEM cache magic does not match.  Failed to free memory: %p", value);
            CB_BUG();
        }
    }
}

void *ec_mem_get(void *value, ProcessContext *context)
{
    if (value)
    {
        generic_buffer_t *generic_buffer = (generic_buffer_t *)((char *)value - sizeof(generic_buffer_t));

        if (generic_buffer->magic == GENERIC_BUFFER_MAGIC)
        {
            atomic64_inc(&generic_buffer->ref_count);
        } else
        {
            value = 0;
            TRACE(DL_ERROR, "Generic MEM cache magic does not match.  Failed to free memory: %p", value);
            CB_BUG();
        }
    }
    return value;
}

size_t ec_mem_size(const void *value)
{
    size_t size = 0;

    if (value)
    {
        generic_buffer_t *generic_buffer = (generic_buffer_t *)((char *)value - sizeof(generic_buffer_t));

        if (generic_buffer->magic == GENERIC_BUFFER_MAGIC)
        {
            size = generic_buffer->size - GENERIC_BUFFER_SZ;
        } else
        {
            TRACE(DL_ERROR, "Generic MEM cache magic does not match.  Failed to free memory: %p", value);
            CB_BUG();
        }
    }
    return size;
}

char *ec_mem_strdup(const char *src, ProcessContext *context)
{
    return __ec_mem_strdup(src, 0, context);
}

char *ec_mem_memdup(const char *src, size_t size, ProcessContext *context)
{
    return __ec_mem_strdup(src, size, context);
}

char *__ec_mem_strdup(const char *src, size_t size_in, ProcessContext *context)
{
    char *dest = NULL;
    size_t len = size_in;

    if (src)
    {
        if (size_in == 0)
        {
            // If we were not provided a size_in, calculate the string length
            len = strlen(src);
        }

        // Allocate memory to hold the data we want to copy and add an extra character for a NULL termination.
        dest = ec_mem_alloc(len + 1, context);
        if (dest)
        {
            // This covers two possible cases for us.
            //  1. The is a NULL terminated string that we are duplicating.  In this case we calculated 'len' from the
            //     string length.
            //  2. We were provided a size at input which may not be null terminated.
            //
            //  For both cases we set the last character to NULL to be safe.
            memcpy(dest, src, len);
            dest[len] = 0;
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
