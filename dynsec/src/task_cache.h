/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once
extern int task_cache_register(void);
extern void task_cache_shutdown(void);
extern int task_cache_set_last_event(struct dynsec_event *hdr,
                              uint64_t *prev_req_id,
                              enum dynsec_event_type *prev_event_type,
                              gfp_t mode);
extern int task_cache_handle_response(struct dynsec_response *response);
extern void task_cache_clear_response_caches(pid_t tid);
extern void task_cache_remove_entry(pid_t tid);

