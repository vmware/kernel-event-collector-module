// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
#include <linux/tracepoint.h>
#else
#include <trace/events/sched.h>
#endif
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include "dynsec.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern void dynsec_sched_process_fork_tp(void *data, struct task_struct *parent,
                                  struct task_struct *child);
#else
extern void dynsec_sched_process_fork_tp(struct task_struct *parent,
                                  struct task_struct *child);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern void dynsec_sched_process_exit_tp(void *data,
                                         struct task_struct *task);
#else
extern void dynsec_sched_process_exit_tp(struct task_struct *task);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern void dynsec_sched_process_free_tp(void *data, struct task_struct *task);
#else
extern void dynsec_sched_process_free_tp(struct task_struct *task);
#endif

extern int dynsec_wake_up_new_task(struct kprobe *kprobe, struct pt_regs *regs);

static DEFINE_MUTEX(tp_lock);
uint32_t enabled_process_hooks = 0;
struct kprobe *new_task_kprobe = NULL;
struct kprobe __new_task_kprobe;

#define lock_tp() mutex_lock(&tp_lock);
#define unlock_tp() mutex_unlock(&tp_lock);

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
struct tp {
    bool enabled;
    struct tracepoint *tp;
    char *name;
    void *hook;
};
#define TP_CLONE_IDX        0
#define TP_EXIT_IDX         1
#define TP_TASK_FREE_IDX    2
#define TP_MAX_IDX          3
struct dynsec_tracepoints {
    struct tp tp[TP_MAX_IDX];
    int count;
    int registered;
};

struct dynsec_tracepoints dtp = {
    .tp = {
        // dynsec_sched_process_fork_tp is only a backup hook
        // to when wake_up_new_task isn't available.
        [TP_CLONE_IDX] = {
            .enabled = false,
            .tp = NULL,
            .name = "sched_process_fork",
            .hook = dynsec_sched_process_fork_tp,
        },
        [TP_EXIT_IDX] = {
            .enabled = false,
            .tp = NULL,
            .name = "sched_process_exit",
            .hook = dynsec_sched_process_exit_tp,
        },
        [TP_TASK_FREE_IDX] = {
            .enabled = false,
            .tp = NULL,
            .name = "sched_process_free",
            .hook = dynsec_sched_process_free_tp,
        },
    },
    .count = 0,
    .registered = 0,
};

static void tracepoint_itr_cb(struct tracepoint *tp, void *data)
{
    int i;
    struct dynsec_tracepoints *dtp = data;

    if (dtp->count == dtp->registered) {
        return;
    }

    for (i = 0; i < ARRAY_SIZE(dtp->tp); i++) {
        if (dtp->tp[i].tp || !dtp->tp[i].enabled) {
            continue;
        }
        if (strcmp(tp->name, dtp->tp[i].name) != 0) {
            continue;
        }

        dtp->tp[i].tp = tp;
        dtp->registered += 1;
        break;
    }
}
#endif

static void dummy_post_handler(struct kprobe *p, struct pt_regs *regs,
                unsigned long flags)
{
}
static int dummy_fault_handler(struct kprobe *kprobe, struct pt_regs *regs, int trapnr)
{
    return 0;
}

// hold tp_lock
static void __enable_clone_tp(uint32_t tp_hooks)
{
    if (enabled_process_hooks & DYNSEC_TP_HOOK_TYPE_CLONE) {
        return;
    }

    if (!(tp_hooks & DYNSEC_TP_HOOK_TYPE_CLONE)) {
        return;
    }

    new_task_kprobe = &__new_task_kprobe;
    memset(new_task_kprobe, 0, sizeof(*new_task_kprobe));
    new_task_kprobe->symbol_name = "wake_up_new_task";
    new_task_kprobe->pre_handler   = dynsec_wake_up_new_task;
    new_task_kprobe->post_handler  = dummy_post_handler;
    new_task_kprobe->fault_handler = dummy_fault_handler;

    if (register_kprobe(new_task_kprobe) >= 0 || new_task_kprobe->addr) {
        enabled_process_hooks |= DYNSEC_TP_HOOK_TYPE_CLONE;
        return;
    }
    new_task_kprobe = NULL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    if (dtp.tp[TP_CLONE_IDX].tp && dtp.tp[TP_CLONE_IDX].hook) {
        tracepoint_probe_register(dtp.tp[TP_CLONE_IDX].tp,
                                  dtp.tp[TP_CLONE_IDX].hook, NULL);
        enabled_process_hooks |= DYNSEC_TP_HOOK_TYPE_CLONE;
    }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
    register_trace_sched_process_fork(dynsec_sched_process_fork_tp, NULL);
    enabled_process_hooks |= DYNSEC_TP_HOOK_TYPE_CLONE;
#else
    register_trace_sched_process_fork(dynsec_sched_process_fork_tp);
    enabled_process_hooks |= DYNSEC_TP_HOOK_TYPE_CLONE;
#endif
}

// hold tp_lock
static void __enable_exit_tp(uint32_t tp_hooks)
{
    if (enabled_process_hooks & DYNSEC_TP_HOOK_TYPE_EXIT) {
        return;
    }

    if (!(tp_hooks & DYNSEC_TP_HOOK_TYPE_EXIT)) {
        return;
    }

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    if (dtp.tp[TP_EXIT_IDX].tp && dtp.tp[TP_EXIT_IDX].hook) {
        tracepoint_probe_register(dtp.tp[TP_EXIT_IDX].tp,
                                  dtp.tp[TP_EXIT_IDX].hook, NULL);
        enabled_process_hooks |= DYNSEC_TP_HOOK_TYPE_EXIT;
    }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
    register_trace_sched_process_exit(dynsec_sched_process_exit_tp, NULL);
    enabled_process_hooks |= DYNSEC_TP_HOOK_TYPE_EXIT;
#else
    register_trace_sched_process_exit(dynsec_sched_process_exit_tp);
    enabled_process_hooks |= DYNSEC_TP_HOOK_TYPE_EXIT;
#endif
}

// hold tp_lock
static void __enable_task_free_tp(uint32_t tp_hooks)
{
    if (enabled_process_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE) {
        return;
    }

    if (!(tp_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE)) {
        return;
    }

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    if (dtp.tp[TP_TASK_FREE_IDX].tp && dtp.tp[TP_TASK_FREE_IDX].hook) {
        tracepoint_probe_register(dtp.tp[TP_TASK_FREE_IDX].tp,
                                  dtp.tp[TP_TASK_FREE_IDX].hook, NULL);
        enabled_process_hooks |= DYNSEC_TP_HOOK_TYPE_TASK_FREE;
    }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
    register_trace_sched_process_free(dynsec_sched_process_free_tp, NULL);
    enabled_process_hooks |= DYNSEC_TP_HOOK_TYPE_TASK_FREE;
#else
    register_trace_sched_process_free(dynsec_sched_process_free_tp);
    enabled_process_hooks |= DYNSEC_TP_HOOK_TYPE_TASK_FREE;
#endif
}

// hold tp_lock
static void __disable_clone_tp(void)
{
    if (!(enabled_process_hooks & DYNSEC_TP_HOOK_TYPE_CLONE)) {
        return;
    }

    enabled_process_hooks &= ~(DYNSEC_TP_HOOK_TYPE_CLONE);

    if (new_task_kprobe) {
        unregister_kprobe(new_task_kprobe);
        new_task_kprobe = NULL;
        return;
    }

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    if (dtp.tp[TP_CLONE_IDX].tp && dtp.tp[TP_CLONE_IDX].hook) {
        tracepoint_probe_unregister(dtp.tp[TP_CLONE_IDX].tp,
                                    dtp.tp[TP_CLONE_IDX].hook, NULL);
    }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
    unregister_trace_sched_process_fork(dynsec_sched_process_fork_tp, NULL);
#else
    unregister_trace_sched_process_fork(dynsec_sched_process_fork_tp);
#endif
}

// hold tp_lock
static void __disable_exit_tp(void)
{
    if (!(enabled_process_hooks & DYNSEC_TP_HOOK_TYPE_EXIT)) {
        return;
    }

    enabled_process_hooks &= ~(DYNSEC_TP_HOOK_TYPE_EXIT);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    if (dtp.tp[TP_EXIT_IDX].tp && dtp.tp[TP_EXIT_IDX].hook) {
        tracepoint_probe_unregister(dtp.tp[TP_EXIT_IDX].tp,
                                    dtp.tp[TP_EXIT_IDX].hook, NULL);
    }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
    unregister_trace_sched_process_exit(dynsec_sched_process_exit_tp, NULL);
#else
    unregister_trace_sched_process_exit(dynsec_sched_process_exit_tp);
#endif
}

// hold tp_lock
static void __disable_task_free_tp(void)
{
    if (!(enabled_process_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE)) {
        return;
    }

    enabled_process_hooks &= ~(DYNSEC_TP_HOOK_TYPE_TASK_FREE);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    if (dtp.tp[TP_TASK_FREE_IDX].tp && dtp.tp[TP_TASK_FREE_IDX].hook) {
        tracepoint_probe_unregister(dtp.tp[TP_TASK_FREE_IDX].tp,
                                    dtp.tp[TP_TASK_FREE_IDX].hook, NULL);
    }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
    unregister_trace_sched_process_free(dynsec_sched_process_free_tp, NULL);
#else
    unregister_trace_sched_process_free(dynsec_sched_process_free_tp);
#endif
}

bool may_enable_task_cache(void)
{
    return (enabled_process_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE);
}

void dynsec_tp_shutdown(void)
{
    if (enabled_process_hooks) {
        mutex_lock(&tp_lock);
        __disable_clone_tp();
        __disable_exit_tp();
        __disable_task_free_tp();
        mutex_unlock(&tp_lock);
    }

    tracepoint_synchronize_unregister();
}

bool dynsec_init_tp(struct dynsec_config *dynsec_config)
{
    uint64_t process_hooks = 0;
    enabled_process_hooks = 0;
    new_task_kprobe = NULL;

    if (!dynsec_config) {
        return true;
    }
    process_hooks = dynsec_config->process_hooks;

    lock_tp();
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    if (!new_task_kprobe && (process_hooks & DYNSEC_TP_HOOK_TYPE_CLONE)) {
        dtp.tp[TP_CLONE_IDX].enabled = true;
        dtp.count += 1;
    }
    if (process_hooks & DYNSEC_TP_HOOK_TYPE_EXIT) {
        dtp.tp[TP_EXIT_IDX].enabled = true;
        dtp.count += 1;
    }
    if (process_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE) {
        dtp.tp[TP_TASK_FREE_IDX].enabled = true;
        dtp.count += 1;
    }

    if (dtp.count) {
        for_each_kernel_tracepoint(tracepoint_itr_cb, &dtp);
    }
#endif

    __enable_clone_tp(process_hooks);
    __enable_exit_tp(process_hooks);
    __enable_task_free_tp(process_hooks);

    unlock_tp();

    dynsec_config->process_hooks = enabled_process_hooks;

    return true;
}
