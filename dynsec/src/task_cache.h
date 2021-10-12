/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

struct event_track {
// Primarily for intents that don't make it to userspace
// still have value to cache eviction options.
#define TRACK_EVENT_REPORTABLE          0x0001
#define TRACK_EVENT_REQ_ID_VALID        0x0002
// Would let us know report_flags was modified
#define TRACK_EVENT_REPORT_FLAGS_CHG    0x0004
    uint16_t track_flags;
    uint16_t report_flags;
    enum dynsec_event_type event_type;
    uint64_t req_id;
};

extern int task_cache_register(void);
extern void task_cache_shutdown(void);
extern int task_cache_set_last_event(pid_t tid, struct event_track *event,
                                     struct event_track *prev_event, gfp_t mode);
extern int task_cache_handle_response(struct dynsec_response *response);
extern void task_cache_clear_response_caches(pid_t tid);
extern void task_cache_remove_entry(pid_t tid);
extern void task_cache_clear(void);
extern void task_cache_disable(void);
extern void task_cache_enable(void);
