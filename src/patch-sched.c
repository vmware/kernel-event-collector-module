// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "patch-sched.h"
#include "page-helpers.h"
#include "cb-spinlock.h"

/*
 *  A major problem we have been wrestling with since working on this module is the problem with our
 *  pre and post clone calls. Both calls happen in the context of the parent. The pre-clone call does
 *  not have all the information it needs to update the child's process-tracking entry. When the post
 *  clone call gets called, the child is often already running it needs that tracking entry yesterday.
 *
 *  In order to fix this, I dug through the kernel source and found a method (function pointer)
 *  on the scheduler that is called when a task is being woken up for the very first time.
 *  This means that we can patch the function pointer on the instance of the CFS and it will call
 *  into our hook whenever a new task is woken up for the first time. We then have to make sure to still call
 * the original function to schedule the task.
 * We also need to make sure that we patch all the schedulers which are available through
 * userspace via the sched_setscheduler and sched_setattr calls. this includes
 * fiar, rt, dl, and idle
 *  -PR
 */

static unsigned long page_rw_set;

// this is the signature of the enqueue_task function, using void* where we are missing struct defs
// keep a copy for each sched_class we patch. we patch all sched_classes except for
// stop_sched_class, because that one is performance critical and cannot be reached from usermode anyway
typedef void (*enqueue_task_t) (void *, struct task_struct *, int);

static enqueue_task_t original_enqueue_task_fair;
static enqueue_task_t original_enqueue_task_idle;
static enqueue_task_t original_enqueue_task_rt;

// utilities used in this file
static void enqueue_task_wrapper(void *rq, struct task_struct *p, int flags);
static void original_enqueue_task_mltplx(void *rq, struct task_struct *p, int flags);

static bool _patch_sched(const struct sched_class *sched, enqueue_task_t *original_enqueue_task);
static bool _restore_sched(const struct sched_class *sched, enqueue_task_t original_enqueue_task);
static bool _sched_changed(const struct sched_class *sched);

/* The struct definition for this is not exported so we have
 * to do some pointer arithmetic to get the right function pointer.
 * we add one pointer size to the address because the function is the second
 * entry in the struct.
 *
 * to get the correct offset look in kernel/sched/sched.h (in 3.x) and
 * linux/sched.h (in 2.x). go to the definition of struct sched_class and
 * look for the function enqueue_task. multiply the offset (here is 1 in all
 * supported versions) by the pointer size (8).
 */

#if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7, 8)
// When we support a new kernel version we should manually increment this version.
// This is because this offset could theoretically change and we want to make sure
// that we always confirm it is correct.
#define ENQUEUE_TASK_PTR(SCHED_PTR) \
    ((void **) (((void *) SCHED_PTR) + 1 * sizeof(void *)))
#endif

bool patch_sched(ProcessContext *context)
{
    // set all values to null so if we fail we know which ones to restore
    original_enqueue_task_fair = NULL;
    original_enqueue_task_rt   = NULL;
    original_enqueue_task_idle = NULL;

    TRY(_patch_sched(
        CB_RESOLVED(fair_sched_class),
        &original_enqueue_task_fair));

    TRY(_patch_sched(
        CB_RESOLVED(rt_sched_class),
        &original_enqueue_task_rt));

    TRY(_patch_sched(
        CB_RESOLVED(idle_sched_class),
        &original_enqueue_task_idle));

    return true;

CATCH_DEFAULT:
    return false;
}

static bool _patch_sched(const struct sched_class *sched, enqueue_task_t *original_enqueue_task)
{
    if (sched == NULL)
    {
        TRACE(DL_ERROR, "unable to find sched pointer\n");
        return false;
    }

    *original_enqueue_task = *ENQUEUE_TASK_PTR(sched);

    // mark page as writeable
    if (!set_page_state_rw(ENQUEUE_TASK_PTR(sched), &page_rw_set))
    {
        TRACE(DL_ERROR, "error setting page state in patch_sched\n");
        return false;
    }

    // overwrite the function pointer
    __sync_synchronize(); // memory barrier to reduce likely-hood of read after partial write
    *ENQUEUE_TASK_PTR(sched) = &enqueue_task_wrapper;
    __sync_synchronize();

    restore_page_state(ENQUEUE_TASK_PTR(sched), page_rw_set);

    TRACE(DL_INFO, "Fork hook has been inserted\n");
    return true;
}

void restore_sched(ProcessContext *context)
{

    TRY(_restore_sched(
        CB_RESOLVED(fair_sched_class),
        original_enqueue_task_fair));

    TRY(_restore_sched(
        CB_RESOLVED(rt_sched_class),
        original_enqueue_task_rt));

    TRY(_restore_sched(
        CB_RESOLVED(idle_sched_class),
        original_enqueue_task_idle));

CATCH_DEFAULT:
    return;
}

static bool _restore_sched(const struct sched_class *sched, enqueue_task_t original_enqueue_task)
{
    if (sched == NULL)
    {
        TRACE(DL_ERROR, "unable to find sched for restore\n");
        return false;
    }

    if (original_enqueue_task == NULL)
    {
        TRACE(DL_ERROR, "unable to find original function for restore\n");
        return false;
    }

    // mark page as writeable
    if (!set_page_state_rw(ENQUEUE_TASK_PTR(sched), &page_rw_set))
    {
        TRACE(DL_ERROR, "error setting page state in restore_sched\n");
        return false;
    }

    // overwrite the function pointer
    __sync_synchronize(); // memory barrier to reduce likely-hood of read after partial write
    *ENQUEUE_TASK_PTR(sched) = original_enqueue_task;
    __sync_synchronize();

    restore_page_state(ENQUEUE_TASK_PTR(sched), page_rw_set);
    return true;
}

bool sched_changed(ProcessContext *context)
{
    TRY(_sched_changed(
        CB_RESOLVED(fair_sched_class)));

    TRY(_sched_changed(
        CB_RESOLVED(rt_sched_class)));

    TRY(_sched_changed(
        CB_RESOLVED(idle_sched_class)));

    return true;

CATCH_DEFAULT:
    return false;
}

static bool _sched_changed(const struct sched_class *sched)
{
    if (sched == NULL)
    {
        return false;
    }

    return *ENQUEUE_TASK_PTR(sched) != (void *) &enqueue_task_wrapper;
}

static void enqueue_task_wrapper(void *rq, struct task_struct *p, int flags)
{
    DECLARE_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // ignore kernel tasks (swapper, migrate, etc)
    // this is critial because path lookups for these functions will schedule
    // and deadlock the system
    TRY(p->mm != NULL);

    // only hook for tasks which are new and have not yet run
    TRY(p->se.sum_exec_runtime == 0);

    // Do not allow any calls to schedule tasks
    DISABLE_WAKE_UP(&context);

    cb_clone_hook(&context, p);

CATCH_DEFAULT:
    original_enqueue_task_mltplx(rq, p, flags);
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return;
}

static void original_enqueue_task_mltplx(void *rq, struct task_struct *p, int flags)
{
    // call the original enqueue method for the task's scheduler

    if (p->sched_class == CB_RESOLVED(fair_sched_class))
    {
        original_enqueue_task_fair(rq, p, flags);
    } else if (p->sched_class == CB_RESOLVED(rt_sched_class))
    {
        original_enqueue_task_rt(rq, p, flags);
    } else if (p->sched_class == CB_RESOLVED(idle_sched_class))
    {
        original_enqueue_task_idle(rq, p, flags);
    }
}
