/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#pragma once

#include <linux/mutex.h>

// Lock primarily to control ioctl interface.
extern struct mutex global_config_lock;

extern struct dynsec_config global_config;

#define DEFAULT_DISABLED 0
#define DEFAULT_ENABLED  1
#define DEFAULT_QUEUE_WATERMARK 0
#define DEFAULT_NOTIFY_WATERMARK 0

#define DEFAULT_WAIT_TIMEOUT_MS 1000
#define MAX_WAIT_TIMEOUT_MS     15000

// TODO: Add wait_timeout field
#define DEFINE_DYNSEC_CONFIG(config_name) struct dynsec_config \
    config_name = { \
    .bypass_mode = DEFAULT_DISABLED, \
    .stall_mode = DEFAULT_ENABLED, \
    .stall_timeout = DEFAULT_WAIT_TIMEOUT_MS, \
    .lazy_notifier = DEFAULT_ENABLED, \
    .queue_threshold = DEFAULT_QUEUE_WATERMARK, \
    .notify_threshold = DEFAULT_NOTIFY_WATERMARK, \
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

#define get_notify_threshold() (global_config.notify_threshold)
#define get_queue_threshold() (global_config.queue_threshold)
#define get_wait_timeout() (global_config.stall_timeout)
