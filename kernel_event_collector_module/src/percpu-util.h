/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

#include <linux/version.h>
#include <linux/percpu_counter.h>
#include <linux/percpu-refcount.h>

#if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7, 1)
#define ec_percpu_counter_init(fbc, value, gfp)  percpu_counter_init(fbc, value)
#define ec_alloc_percpu(type, gfp)               alloc_percpu(type)
#else
#define ec_percpu_counter_init(fbc, value, gfp)  percpu_counter_init(fbc, value, gfp)
#define ec_alloc_percpu(type, gfp)               alloc_percpu_gfp(type, gfp)
#endif


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
