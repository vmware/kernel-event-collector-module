/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

#include <linux/mutex.h>

// Lock primarily to control ioctl interface.
extern struct mutex global_config_lock;

// Transient for current client config options.
extern struct dynsec_config global_config __read_mostly;
// Use to reset global_config on client disconnect. Immutable for now.
extern struct dynsec_config preserved_config __read_mostly;

#define DEFAULT_DISABLED 0
#define DEFAULT_ENABLED  1
#define DEFAULT_QUEUE_WATERMARK 64
#define DEFAULT_NOTIFY_WATERMARK 8

#define MIN_WAIT_TIMEOUT_MS     1000
#define MAX_WAIT_TIMEOUT_MS     15000
#define DEFAULT_WAIT_TIMEOUT_MS 5000
#define MAX_EXTENDED_TIMEOUT_MS 1800000

#define DEFINE_DYNSEC_CONFIG(config_name) struct dynsec_config \
    config_name = { \
    .bypass_mode = DEFAULT_DISABLED, \
    .stall_mode = DEFAULT_ENABLED, \
    .stall_timeout = DEFAULT_WAIT_TIMEOUT_MS, \
    .stall_timeout_continue = MAX_WAIT_TIMEOUT_MS, \
    .stall_timeout_deny = DEFAULT_DISABLED, \
    .lazy_notifier = DEFAULT_ENABLED, \
    .queue_threshold = DEFAULT_QUEUE_WATERMARK, \
    .notify_threshold = DEFAULT_NOTIFY_WATERMARK, \
    .send_files = DEFAULT_DISABLED, \
    .protect_mode = DEFAULT_DISABLED, \
    .ignore_mode = DEFAULT_ENABLED, \
    .lsm_hooks = DYNSEC_LSM_HOOKS, \
    .process_hooks = DYNSEC_PROCESS_HOOKS, \
    .preaction_hooks = 0, \
}

#define lock_config() mutex_lock(&global_config_lock);
#define unlock_config() mutex_unlock(&global_config_lock);


// Primitive helper macros until we start
// creating a client instance object and setting things per-client.
// However some settings should remain global and some per-client.
#define stall_mode_enabled() (global_config.stall_mode != 0)
#define bypass_mode_enabled() (global_config.bypass_mode != 0)
#define lazy_notifier_enabled() (global_config.lazy_notifier != 0)
#define meets_notify_threshold(size) \
    (global_config.notify_threshold > 0 && size >= global_config.notify_threshold)
#define send_open_file_enabled() (global_config.send_files != 0)

#define get_notify_threshold() (global_config.notify_threshold)
#define get_queue_threshold() (global_config.queue_threshold)
#define get_wait_timeout() (global_config.stall_timeout)
#define protect_mode_enabled() (global_config.protect_mode != DEFAULT_DISABLED)
#define ignore_mode_enabled() (global_config.ignore_mode != DEFAULT_DISABLED)
#define deny_on_timeout_enabled() (global_config.stall_timeout_deny != DEFAULT_DISABLED)
#define get_continue_timeout() (global_config.stall_timeout_continue)
