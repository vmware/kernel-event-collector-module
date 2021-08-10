// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
#include <linux/tracepoint.h>
#else
#include <trace/events/sched.h>
#endif
#include "dynsec.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern void dynsec_sched_process_fork_tp(void *data,
                                         struct task_struct *parent,
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


#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
struct tp {
    bool enabled;
    struct tracepoint *tp;
    char *name;
    void *hook;
};
struct dynsec_tracepoints {
    struct tp tp[3];
    int count;
    int registered;
};

struct dynsec_tracepoints dtp = {
    .tp = {
        [0] = {
            .enabled = false,
            .tp = NULL,
            .name = "sched_process_fork",
            .hook = dynsec_sched_process_fork_tp,
        },
        [1] = {
            .enabled = false,
            .tp = NULL,
            .name = "sched_process_exit",
            .hook = dynsec_sched_process_exit_tp,
        },
        [2] = {
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

bool dynsec_init_tp(uint64_t tp_hooks)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_CLONE) {
        dtp.tp[0].enabled = true;
        dtp.count += 1;
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_EXIT) {
        dtp.tp[1].enabled = true;
        dtp.count += 1;
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE) {
        dtp.tp[2].enabled = true;
        dtp.count += 1;
    }

    if (dtp.count) {
        for_each_kernel_tracepoint(tracepoint_itr_cb, &dtp);
    }
    if (dtp.count != dtp.registered) {
        return false;
    }

    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_CLONE) {
        if (dtp.tp[0].tp) {
            tracepoint_probe_register(dtp.tp[0].tp, dtp.tp[0].hook, NULL);
        }
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_EXIT) {
        if (dtp.tp[1].tp) {
            tracepoint_probe_register(dtp.tp[1].tp, dtp.tp[1].hook, NULL);
        }
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE) {
        if (dtp.tp[2].tp) {
            tracepoint_probe_register(dtp.tp[2].tp, dtp.tp[2].hook, NULL);
        }
    }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_CLONE) {
        register_trace_sched_process_fork(dynsec_sched_process_fork_tp, NULL);
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_EXIT) {
        register_trace_sched_process_exit(dynsec_sched_process_exit_tp, NULL);
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE) {
        register_trace_sched_process_free(dynsec_sched_process_free_tp, NULL);
    }
#else
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_CLONE) {
        register_trace_sched_process_fork(dynsec_sched_process_fork_tp);
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_EXIT) {
        register_trace_sched_process_exit(dynsec_sched_process_exit_tp);
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE) {
        register_trace_sched_process_free(dynsec_sched_process_free_tp);
    }
#endif

    return true;
}

void dynsec_tp_shutdown(uint64_t tp_hooks)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_CLONE) {
        if (dtp.tp[0].tp) {
            tracepoint_probe_unregister(dtp.tp[0].tp, dtp.tp[0].hook, NULL);
        }
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_EXIT) {
        if (dtp.tp[1].tp) {
            tracepoint_probe_unregister(dtp.tp[1].tp, dtp.tp[1].hook, NULL);
        }
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE) {
        if (dtp.tp[2].tp) {
            tracepoint_probe_unregister(dtp.tp[2].tp, dtp.tp[2].hook, NULL);
        }
    }
#elif LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_CLONE) {
        unregister_trace_sched_process_fork(dynsec_sched_process_fork_tp, NULL);
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_EXIT) {
        unregister_trace_sched_process_exit(dynsec_sched_process_exit_tp, NULL);
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE) {
        unregister_trace_sched_process_free(dynsec_sched_process_free_tp, NULL);
    }
#else
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_CLONE) {
        unregister_trace_sched_process_fork(dynsec_sched_process_fork_tp);
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_EXIT) {
        unregister_trace_sched_process_exit(dynsec_sched_process_exit_tp);
    }
    if (tp_hooks & DYNSEC_TP_HOOK_TYPE_TASK_FREE) {
        unregister_trace_sched_process_free(dynsec_sched_process_free_tp);
    }
#endif
}
