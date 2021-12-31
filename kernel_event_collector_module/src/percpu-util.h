/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

#include <linux/version.h>
#include <linux/percpu_counter.h>

#include "cb-test.h"

#if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7, 1)
#define ec_percpu_counter_init(fbc, value, gfp)  percpu_counter_init(fbc, value)
#define ec_alloc_percpu(type, gfp)               alloc_percpu(type)
#define ec_percpu_ref_init(ref, cb, flags, gfp)  percpu_ref_init(ref, cb)

struct percpu_ref;

typedef void (percpu_ref_func_t)(struct percpu_ref *);

struct percpu_ref {
    atomic64_t count;
    percpu_ref_func_t *release_callback;
};

static inline int __must_check percpu_ref_init(
    struct percpu_ref *ref,
	percpu_ref_func_t *release)
{
    CANCEL(ref, 1);

    atomic64_set(&ref->count, 1);
    ref->release_callback = release;

    return 0;
}

static inline void percpu_ref_exit(struct percpu_ref *ref)
{
}

static inline void percpu_ref_get(struct percpu_ref *ref)
{
    CANCEL_VOID(ref);

     atomic64_inc(&ref->count);
}

static inline void percpu_ref_put(struct percpu_ref *ref)
{
    CANCEL_VOID(ref);

     IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(&ref->count, {
         if (ref->release_callback)
         {
             ref->release_callback(ref);
         }
     });
}

static inline void percpu_ref_kill_and_confirm(
    struct percpu_ref *ref,
	percpu_ref_func_t *confirm_kill)
{
    CANCEL_VOID(ref);

    percpu_ref_put(ref);
    confirm_kill(ref);
}

static inline int64_t percpu_ref_sum(struct percpu_ref *ref)
{
    CANCEL(ref, 0);

    return atomic64_read(&ref->count);
}

#else
#include <linux/percpu-refcount.h>

#define ec_percpu_counter_init(fbc, value, gfp)  percpu_counter_init(fbc, value, gfp)
#define ec_alloc_percpu(type, gfp)               alloc_percpu_gfp(type, gfp)
#define ec_percpu_ref_init(ref, cb, flags, gfp)  percpu_ref_init(ref, cb, flags, gfp)

/**
 * percpu_ref_put - decrement a percpu refcount
 * @ref: percpu_ref to put
 *
 * Decrement the refcount, and if 0, call the release function (which was passed
 * to percpu_ref_init())
 *
 * This function is safe to call as long as @ref is between init and exit.
 */
static inline int64_t percpu_ref_sum(struct percpu_ref *ref)
{
    unsigned long __percpu *percpu_count;
    unsigned int cpu;
    int64_t sum = 0;

    rcu_read_lock_sched();

    if (__ref_is_percpu(ref, &percpu_count))
    {
        for_each_online_cpu(cpu)
        {
            sum += per_cpu(*percpu_count, cpu);
        }
    } else
    {
        sum = atomic_long_read(&ref->count);
    }

    rcu_read_unlock_sched();

    return sum;
}
#endif
