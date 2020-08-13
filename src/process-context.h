/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once


// checkpatch-ignore: COMPLEX_MACRO

#include <linux/types.h>
#include <linux/time.h>
#include <linux/gfp.h>
#include "dbg.h"

extern struct timespec get_current_timespec(void);

#define __CONTEXT_INITIALIZER(NAME, MODE, PID) {                               \
    .gfp_mode              = { (MODE), },                                      \
    .stack_index           = 0,                                                \
    .pid                   = (PID),                                            \
    .allow_wake_up         = true,                                             \
    .allow_send_events     = true,                                             \
    .hook_name             = __func__,                                         \
    .enter_time            = get_current_timespec(),                           \
    .list                  = LIST_HEAD_INIT((NAME).list),                      \
    .decr_active_call_count_on_exit = false                                    \
}

#define MAX_GFP_STACK    10

#define CB_ATOMIC        (GFP_ATOMIC | GFP_NOWAIT)

#define DECLARE_ATOMIC_CONTEXT(name, pid)                                      \
    ProcessContext name = __CONTEXT_INITIALIZER(name, CB_ATOMIC, pid)

#define DECLARE_NON_ATOMIC_CONTEXT(name, pid)                                  \
    ProcessContext name = __CONTEXT_INITIALIZER(name, GFP_KERNEL, pid)

#define DISABLE_WAKE_UP(context)                                               \
    (context)->allow_wake_up = false

#define ENABLE_WAKE_UP(context)                                                \
    (context)->allow_wake_up = true

#define DISABLE_SEND_EVENTS(context)                                               \
    (context)->allow_send_events = false

#define ENABLE_SEND_EVENTS(context)                                                \
    (context)->allow_send_events = true

#define GFP_MODE(context)            (context)->gfp_mode[(context)->stack_index]
#define IS_ATOMIC(context)           (GFP_MODE(context) & GFP_ATOMIC)
#define IS_NON_ATOMIC(context)       (GFP_MODE(context) & GFP_KERNEL)
#define ALLOW_WAKE_UP(context)       (context)->allow_wake_up
#define ALLOW_SEND_EVENTS(context)   (context)->allow_send_events

// checkpatch-ignore: SUSPECT_CODE_INDENT
#define PUSH_GFP_MODE(context, MODE) \
    do {\
        if ((context)->stack_index < MAX_GFP_STACK) {\
            (context)->stack_index++;\
            (context)->gfp_mode[(context)->stack_index] = (MODE);\
        } else {\
            TRACE(DL_ERROR, "%s: GFP_MODE overflow", __func__);\
        } \
    } while (0)

#define POP_GFP_MODE(context) \
    do {\
        if ((context)->stack_index > 0) {\
            (context)->stack_index--;\
        } else {\
            TRACE(DL_ERROR, "%s: GFP_MODE underflow", __func__);\
        } \
    } while (0)
// checkpatch-ignore: SUSPECT_CODE_INDENT

typedef struct process_context {
    gfp_t            gfp_mode[MAX_GFP_STACK];
    int              stack_index;
    pid_t            pid;
    bool             allow_wake_up;
    bool             allow_send_events;
    const char      *hook_name;
    struct timespec  enter_time;
    struct list_head list;
    bool             decr_active_call_count_on_exit;
} ProcessContext;
