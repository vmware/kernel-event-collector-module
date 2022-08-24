// SPDX-License-Identifier: GPL-2.0
// Copyright 2022 VMware, Inc. All rights reserved.

#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/wait.h>
#include <linux/seq_file.h>

#include "stall_tbl.h"
#include "stall_reqs.h"
#include "config.h"
#include "inode_cache.h"
#include "task_cache.h"

#define MAX_CONTINUE_RESPONSES 256

// counter to track consecutive stall timeouts
atomic_t  stall_timeout_ctr = ATOMIC_INIT(0);
atomic_t  access_denied_ctr = ATOMIC_INIT(0);

extern uint32_t stall_timeout_ctr_limit;

static int do_stall_interruptible(struct stall_entry *entry, int *response)
{
    bool disable_stall_tbl = false;
    int ret = 0;
    int wait_ret;
    int local_response;
    unsigned long local_timeout;
    unsigned long timeout;
    unsigned int continue_count = 0;
    int default_reponse = entry->response;
    // saved event hdr data
    uint32_t tid;
    uint64_t req_id, intent_req_id;
    enum dynsec_event_type event_type;
    uint16_t report_flags;

    // Initial values before we might perform a continuation
    timeout = msecs_to_jiffies(get_wait_timeout());
    local_response = entry->response;
    tid = entry->key.tid;
    req_id = entry->key.req_id;
    event_type = entry->key.event_type;
    report_flags = entry->report_flags;
    intent_req_id = entry->intent_req_id;

retry:
    if (!stall_tbl_enabled(stall_tbl)) {
        return -ECHILD;
    }
    if (!stall_mode_enabled()) {
        return -ECHILD;
    }
    if (bypass_mode_enabled()) {
        return -ECHILD;
    }
    local_timeout = 0;
    local_response = default_reponse;

    // entry->mode could be an atomic
    wait_ret = wait_event_interruptible_timeout(entry->wq,
                                                (entry->mode != DYNSEC_STALL_MODE_STALL),
                                                timeout);
    // Interrupt
    if (wait_ret < 0) {
        // We could opt for a non-deny response here or
        // set back to safe value.

        pr_info("%s: interruped %d\n", __func__, wait_ret);
    }
    // Timedout and conditional not met in time
    else if (wait_ret == 0) {
        // Where default response is desired most and hit most frequently

        // timeout not extended, increament counter
        // for timed_out events.
        atomic_inc(&stall_timeout_ctr);

        // TODO: Generate a GENERIC_AUDIT event here.
        // This is something we should not frequently, observe so send these
        // to userspace.
        pr_info("%s: timedout: tid:%u req_id:%llu event_type:%d report_flags:%#x"
                "intent_req_id:%llu\n", __func__, tid, req_id, event_type,
                report_flags, intent_req_id);

        if (stall_timeout_ctr_limit &&
            atomic_read(&stall_timeout_ctr) >= stall_timeout_ctr_limit) {
            disable_stall_tbl = true;
            pr_warn("Stalling disabled after %d events timed out.\n",
                     stall_timeout_ctr_limit);
        }

        pr_info("%s:%d response:%d timedout:%lu jiffies\n", __func__, __LINE__,
                local_response, timeout);
    }
    // Conditional was true, likely wake_up
    else {
        // reset this value
        atomic_set(&stall_timeout_ctr, 0);

        // Acts more like a memory barrier.
        // Copy all data needed for possible continuation.
        spin_lock(&entry->lock);
        local_response = entry->response;
        local_timeout = entry->stall_timeout;

        // reset mode back to stall will definitely require spin_lock
        entry->mode = DYNSEC_STALL_MODE_STALL;
        // Could copy over requested custom continuation timeout
        spin_unlock(&entry->lock);

        // Userspace wants to extend stalling of this task
        if (local_response == DYNSEC_RESPONSE_CONTINUE) {
            if (local_timeout) {
                timeout = msecs_to_jiffies(local_timeout);
            } else {
                timeout = msecs_to_jiffies(get_continue_timeout());
            }
            continue_count += 1;
            pr_info("%s:%d continue:%u extending stall:%lu jiffies\n",
                    __func__, __LINE__, continue_count, timeout);

            // Don't let userspace ping/pong for too long
            if (continue_count < MAX_CONTINUE_RESPONSES) {
                goto retry;
            }
            ret = -ECHILD;
        }
    }

    if (local_response == DYNSEC_RESPONSE_EPERM) {
        *response = -EPERM;
        atomic_inc(&access_denied_ctr);
    }

    // Must always attempt to remove from the table unless some entry
    // state in the future tells we don't have to.
    stall_tbl_remove_entry(stall_tbl, entry);

    // Call last to prevent potential use-after-free
    if (disable_stall_tbl) {
        stall_tbl_disable(stall_tbl);
        task_cache_clear();
        inode_cache_clear();
        lock_config();
        global_config.stall_mode = DEFAULT_DISABLED;
        unlock_config();
    }

    return ret;
}

// handling calculations to find average time
// maximum time spent in stall table etc.

#define  DYNSEC_RECORDS_TO_AVERAGE    64

DEFINE_SPINLOCK(g_stall_timing_lock);
static u64 g_avg_stall_time, g_max_stall_time;

static void do_stall_timing_records(struct stall_entry *entry)
{
    static bool flag = false;
    static int ctr = 0;
    static u64 sum = 0;
    static u64 stall_times[DYNSEC_RECORDS_TO_AVERAGE];
    int divisor = DYNSEC_RECORDS_TO_AVERAGE;
    ktime_t event_done;

    // stall time calculations.
    event_done = dynsec_current_ktime;
    if (flag) {
        // rotating average of DYNSEC_RECORDS_TO_AVERAGE entries
        sum -= stall_times[ctr]; 
    } else {
        // till ctr reaches DYNSEC_RECORDS_TO_AVERAGE
        divisor = ctr + 1;
    }
    stall_times[ctr] = ktime_to_ns(ktime_sub(event_done, entry->start));

    spin_lock(&g_stall_timing_lock);
    if (stall_times[ctr] > g_max_stall_time) {
        g_max_stall_time = stall_times[ctr];
    }

    sum += stall_times[ctr++];
    g_avg_stall_time = (sum / divisor); 
    spin_unlock(&g_stall_timing_lock);

    if (ctr == DYNSEC_RECORDS_TO_AVERAGE) {
        ctr = 0;
        // flag indicates counter beyond DYNSEC_RECORDS_TO_AVERAGE
        flag = true;
    }
    pr_debug("Stall time logs: %02d: sum: %lld avg: %lld max: %lld\n",
              ctr, sum, g_avg_stall_time, g_max_stall_time);
}

void stall_tbl_wait_statistics(struct seq_file *m)
{
    u64 avg, max;
    spin_lock(&g_stall_timing_lock);
    avg = g_avg_stall_time;
    max = g_max_stall_time;
    spin_unlock(&g_stall_timing_lock);
    seq_printf(m, "   stall table average wait time: %lld.%06lld msec",
                  avg/1000000, avg % 1000000);
    seq_puts(m, "\n");
    seq_printf(m, "   stall table average wait time: %lld.%06lld msec",
                  max/1000000, max % 1000000);
    seq_puts(m, "\n");
}

int dynsec_wait_event_timeout(struct dynsec_event *dynsec_event, int *response,
                              gfp_t mode)
{
    struct stall_entry *entry;

    if (!response) {
        return -EINVAL;
    }

    // Regardless default timeout return value,
    // set return value to a safe value.
    *response = 0;

    if (!dynsec_event || !stall_tbl_enabled(stall_tbl)) {
        free_dynsec_event(dynsec_event);
        return -EINVAL;
    }

    // Not the cleanest place to check
    if ((dynsec_event->report_flags & DYNSEC_REPORT_IGNORE) &&
        ignore_mode_enabled()) {
        free_dynsec_event(dynsec_event);
        return -ECHILD;
    }

    entry = stall_tbl_insert(stall_tbl, dynsec_event, mode);
    if (IS_ERR(entry)) {
        free_dynsec_event(dynsec_event);
        return PTR_ERR(entry);
    }

    if (entry) {
        (void)do_stall_interruptible(entry, response);

        // stall table timing calculations
        if (*response == 0)
            do_stall_timing_records(entry);

        // free entry memory here
        kfree(entry);
    }

    return 0;
}


int handle_stall_ioc(const struct dynsec_stall_ioc_hdr *hdr)
{
    unsigned long flags = 0;

    if (!hdr) {
        return -EINVAL;
    }

    flags = hdr->flags;
    flags &= (DYNSEC_STALL_MODE_SET
        | DYNSEC_STALL_DEFAULT_TIMEOUT
        | DYNSEC_STALL_CONTINUE_TIMEOUT
        | DYNSEC_STALL_DEFAULT_DENY
    );
    if (!flags) {
        return -EINVAL;
    }

    if (!capable(CAP_SYS_ADMIN)) {
        return -EPERM;
    }

    lock_config();
    if (flags & DYNSEC_STALL_MODE_SET) {
        if (stall_mode_enabled()) {
            // Disable stalling
            if (hdr->stall_mode == DEFAULT_DISABLED) {
                global_config.stall_mode = DEFAULT_DISABLED;
                task_cache_clear();
                inode_cache_clear();
            }
        } else {
            // Enable stalling
            if (hdr->stall_mode != DEFAULT_DISABLED) {
                task_cache_clear();
                inode_cache_clear();
                global_config.stall_mode = DEFAULT_ENABLED;
                // reset counter
                atomic_set(&stall_timeout_ctr, 0);
                atomic_set(&access_denied_ctr, 0);
            }
        }
    }
    if (flags & DYNSEC_STALL_DEFAULT_TIMEOUT) {
        unsigned long timeout_ms = MAX_WAIT_TIMEOUT_MS;

        if (hdr->stall_timeout < MAX_WAIT_TIMEOUT_MS) {
            timeout_ms = hdr->stall_timeout;
        }
        if (timeout_ms < MIN_WAIT_TIMEOUT_MS) {
            timeout_ms = MIN_WAIT_TIMEOUT_MS;
        }

        global_config.stall_timeout = timeout_ms;
    }
    if (flags & DYNSEC_STALL_CONTINUE_TIMEOUT) {
        unsigned long timeout_ms = MAX_WAIT_TIMEOUT_MS;

        // Ensure our continuation timeout as at least as long as
        // the regular timeout.
        if (hdr->stall_timeout_continue > global_config.stall_timeout) {
            timeout_ms = hdr->stall_timeout_continue;
        } else {
            timeout_ms = global_config.stall_timeout;
        }
        if (timeout_ms > MAX_EXTENDED_TIMEOUT_MS) {
            timeout_ms = MAX_EXTENDED_TIMEOUT_MS;
        }

        global_config.stall_timeout_continue = timeout_ms;
        pr_debug("%s:%d continue stall timeout set to %ld sec.\n", __func__, __LINE__,
                timeout_ms/1000);
    }

    if (flags & DYNSEC_STALL_DEFAULT_DENY) {
        if (deny_on_timeout_enabled()) {
            // Turn off Default Deny
            if (hdr->stall_timeout_deny == DEFAULT_DISABLED) {
                global_config.stall_timeout_deny = DEFAULT_DISABLED;
            }
        } else {
            // Turn on Default Deny
            if (hdr->stall_timeout_deny != DEFAULT_DISABLED) {
                global_config.stall_timeout_deny = DEFAULT_ENABLED;
            }
        }
    }
    unlock_config();

    return 0;
}
