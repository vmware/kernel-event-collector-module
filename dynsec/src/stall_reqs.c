// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/module.h>
#ifndef SINGLE_READ_ONLY
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
#include <linux/sched/signal.h>
#endif
#endif /* ! SINGLE_READ_ONLY */

#include "dynsec.h"
#include "stall_tbl.h"
#include "factory.h"
#include "version.h"
#include "inode_cache.h"
#include "task_cache.h"
#include "hooks.h"
#include "config.h"

static dev_t g_maj_t;
static int maj_no;
static struct cdev dynsec_cdev;

struct stall_tbl *stall_tbl = NULL;

static DEFINE_MUTEX(dump_all_lock);

bool task_in_connected_tgid(const struct task_struct *task)
{
    return (task && stall_tbl && stall_tbl->tgid == task->tgid);
}

int dynsec_wait_event_timeout(struct dynsec_event *dynsec_event, int *response,
                              unsigned int ms, gfp_t mode)
{
    int ret;
    struct stall_entry *entry;
    int local_response = DYNSEC_RESPONSE_ALLOW;
    unsigned long timeout;

    if (!dynsec_event || !response || !stall_tbl_enabled(stall_tbl)) {
        free_dynsec_event(dynsec_event);
        return -EINVAL;
    }

    entry = stall_tbl_insert(stall_tbl, dynsec_event, mode);
    if (IS_ERR(entry)) {
        free_dynsec_event(dynsec_event);
        return PTR_ERR(entry);
    }

    timeout = msecs_to_jiffies(get_wait_timeout());
    ret = wait_event_interruptible_timeout(entry->wq, entry->mode != 0, timeout);
    stall_tbl_remove_entry(stall_tbl, entry);
    if (ret >= 1) {
        // Act as a memory barrier
        // spin_lock(&entry->lock);
        local_response = entry->response;
        // spin_unlock(&entry->lock);
    } else if (ret == 0) {
        // pr_info("%s:%d timedout:%u ms\n", __func__, __LINE__, ms);
    } else {
        // pr_info("%s: interruped %d\n", __func__, ret);
    }

    kfree(entry);
    entry = NULL;

    switch (local_response) {
    case DYNSEC_RESPONSE_EPERM:
        *response = -EPERM;
        break;

    default:
        *response = 0;
        break;
    }

    return 0;
}


// Userspace interfaces

static int dynsec_stall_open(struct inode *inode, struct file *file)
{
    int ret;

    if (stall_tbl_enabled(stall_tbl)) {
        return -EACCES;
    }

    if (!capable(CAP_SYS_ADMIN)) {
        return -EPERM;
    }

    // Add tgid to exceptions ??
    stall_tbl_enable(stall_tbl);

    ret = nonseekable_open(inode, file);

    return ret;
}

static ssize_t dynsec_stall_read(struct file *file, char __user *ubuf,
                                 size_t count, loff_t *pos)
{
    ssize_t ret;
    struct dynsec_event *event;
#ifndef SINGLE_READ_ONLY
    char __user *start = ubuf;
#endif /* ! SINGLE_READ_ONLY */
    u32 total_copied = 0;
    u32 copy_limit = 0;

    lock_config();
    copy_limit = get_queue_threshold();
    unlock_config();

    event = stall_queue_shift(stall_tbl, count);
    if (!event) {
        return -EAGAIN;
    }

    ret = copy_dynsec_event_to_user(event, ubuf, count);
    if (ret < 0) {
        struct stall_key key;
        pr_info("%s:%d size:%u failed copy:%ld\n", __func__, __LINE__,
                stall_queue_size(stall_tbl), ret);

        memset(&key, 0, sizeof(key));
        key.req_id = event->req_id;
        key.event_type = event->event_type;
        key.tid = event->tid;

        // Place it back into queue OR resume task if we
        // don't have a timeout during the stall.
        if (event->report_flags & DYNSEC_REPORT_STALL) {
            stall_tbl_resume(stall_tbl, &key, DYNSEC_RESPONSE_ALLOW, 0);
        }
        free_dynsec_event(event);
        event = NULL;
        goto out;
    }
    free_dynsec_event(event);
    event = NULL;
    count -= ret;
    ubuf += ret;
    total_copied += 1;

#ifndef SINGLE_READ_ONLY
    while (1)
    {
        cond_resched();
        if (signal_pending(current)) {
            ret = ubuf - start;
            goto out;
        }
        event = stall_queue_shift(stall_tbl, count);
        if (!event) {
            ret = ubuf - start;
            goto out;
        }

        ret = copy_dynsec_event_to_user(event, ubuf, count);
        if (ret < 0) {
            struct stall_key key;
            pr_info("%s:%d size:%u failed copy:%ld\n", __func__, __LINE__,
                    stall_queue_size(stall_tbl), ret);

            memset(&key, 0, sizeof(key));
            key.req_id = event->req_id;
            key.event_type = event->event_type;
            key.tid = event->tid;

            // Place it back into queue OR resume task if we
            // don't have a timeout during the stall.
            if (event->report_flags & DYNSEC_REPORT_STALL) {
                stall_tbl_resume(stall_tbl, &key, DYNSEC_RESPONSE_ALLOW, 0);
            }
            free_dynsec_event(event);
            event = NULL;

            // Propagate faults
            if (ret != -EFAULT) {
                ret = ubuf - start;
            }
            goto out;
        }
        free_dynsec_event(event);
        event = NULL;
        count -= ret;
        ubuf += ret;
        total_copied += 1;

        // Stop if there is a hard copy limit and we hit it.
        if (copy_limit && total_copied >= copy_limit) {
            ret = ubuf - start;
            goto out;
        }
    }
#endif /* ! SINGLE_READ_ONLY */

out:

    return ret;
}

static int dynsec_stall_release(struct inode *inode, struct file *file)
{
    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }

    stall_tbl_disable(stall_tbl);
    task_cache_clear();
    inode_cache_clear();

    // Reset back to default settings
    global_config = preserved_config;

    return 0;
}

static unsigned dynsec_stall_poll(struct file *file, struct poll_table_struct *pts)
{
    u32 size;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }

    size = stall_queue_size(stall_tbl);
    if (!size) {
        poll_wait(file, &stall_tbl->queue.wq, pts);

        if (!stall_tbl_enabled(stall_tbl)) {
            return POLLERR;
        }

        size = stall_queue_size(stall_tbl);
        if (size) {
            return POLLIN | POLLRDNORM;
        }
    } else {
        return POLLIN | POLLRDNORM;
    }
    // Lockless approach but no noticable gains
    // if (list_empty_careful(&stall_tbl->queue.list)) {
    //     poll_wait(file, &stall_tbl->queue.wq, pts);
    //     if (!list_empty_careful(&stall_tbl->queue.list)) {
    //         return POLLIN | POLLRDNORM;
    //     }
    // } else {
    //     return POLLIN | POLLRDNORM;
    // }

    return 0;
}

static ssize_t dynsec_stall_write(struct file *file, const char __user *ubuf,
                                  size_t count, loff_t *pos)
{
    struct dynsec_response response;
    struct stall_key key;
    int ret;

    if (sizeof(response) != count) {
        return -EINVAL;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        return -EINVAL;
    }

    if (copy_from_user(&response, ubuf, sizeof(response))) {
        return -EINVAL;
    }

    memset(&key, 0, sizeof(key));
    key.req_id = response.req_id;
    key.event_type = response.event_type;
    key.tid = response.tid;
    ret = stall_tbl_resume(stall_tbl, &key, response.response,
                           response.inode_cache_flags);
    if (ret == 0) {
        if (response.cache_flags) {
            (void)task_cache_handle_response(&response);
        }
        ret = sizeof(response);
    } else if (ret == -ENOENT) {
        // Only accept disable cache opts here
        if (response.cache_flags & (DYNSEC_CACHE_CLEAR|DYNSEC_CACHE_DISABLE)) {
            (void)task_cache_handle_response(&response);
        }
    }

    return ret;
}

static long dynsec_stall_unlocked_ioctl(struct file *file, unsigned int cmd,
                                        unsigned long arg)
{
    int ret = -EINVAL;
    // Check capable() on privileged commands.

    switch (cmd)
    {
    // Dump all tasks or tgids to event queue
    case DYNSEC_IOC_TASK_DUMP_ALL: {
            struct dynsec_task_dump_hdr hdr;

            if (!capable(CAP_SYS_ADMIN)) {
                return -EPERM;
            }

            // Check if we want to directly reply back
            if (copy_from_user(&hdr,
                               (void *)arg, sizeof(hdr))) {
                return -EFAULT;
            }
            if (!(hdr.opts & (DUMP_NEXT_THREAD|DUMP_NEXT_TGID))) {
                return -EINVAL;
            }

            // Let userspace explicitly retry to prevent over-use.
            ret = -EAGAIN;
            if (mutex_trylock(&dump_all_lock)) {
                ret = dynsec_task_dump_all(hdr.opts, hdr.pid);
                mutex_unlock(&dump_all_lock);
            }
        }
        break;

    // Allow client to directly get a dump of task/thread
    case DYNSEC_IOC_TASK_DUMP: {
            struct dynsec_task_dump_hdr hdr;
            struct dynsec_task_dump __user *task_dump_u;
            size_t size;
            ssize_t copied;

            if (!capable(CAP_SYS_ADMIN)) {
                return -EPERM;
            }

            // Check if we want to directly reply back
            if (copy_from_user(&hdr,
                               (void *)arg, sizeof(hdr))) {
                return -EFAULT;
            }
            if (hdr.size < sizeof(struct dynsec_task_dump)) {
                return -EINVAL;
            }
            if (!(hdr.opts & (DUMP_NEXT_THREAD|DUMP_NEXT_TGID))) {
                return -EINVAL;
            }

            task_dump_u = (struct dynsec_task_dump __user *)arg;
            size = hdr.size - offsetof(struct dynsec_task_dump, umsg);
            copied = dynsec_task_dump_one(hdr.opts, hdr.pid,
                                          &task_dump_u->umsg, size);
            if (copied > 0) {
                ret = 0;
            } else {
                ret = copied;
            }
            break;
        }

    // Get the current config settings.
    // Some settings field may be immutable.
    case DYNSEC_IOC_GET_CONFIG:
        if (!capable(CAP_SYS_ADMIN)) {
            return -EPERM;
        }

        if (!arg) {
            ret = -EINVAL;
            break;
        }

        ret = 0;

        // Lock in case called lot in bursts
        lock_config();
        if (copy_to_user((void *)arg, &global_config,
                         sizeof(global_config))) {
            ret = -EFAULT;
        }
        unlock_config();
        break;

    // Bypass Mode in general means we allow the present hooks
    // to just propagate and do nothing else.
    // We may keep basic allocations for the connected client or
    // until the kmod is removed.
    case DYNSEC_IOC_BYPASS_MODE:
        if (!capable(CAP_SYS_ADMIN)) {
            return -EPERM;
        }

        ret = 0;

        // Lock to let one user at time do this operation
        lock_config();
        if (arg) {
            global_config.bypass_mode = 1;
        } else {
            global_config.bypass_mode = 0;
        }

        if (bypass_mode_enabled()) {
            stall_tbl_disable(stall_tbl);
            task_cache_disable();
            inode_cache_disable();
        } else {
            stall_tbl_enable(stall_tbl);
            task_cache_enable();
            inode_cache_enable();
        }
        unlock_config();
        break;

    // Enable/Disable Stall Mode
    case DYNSEC_IOC_STALL_MODE:
        if (!capable(CAP_SYS_ADMIN)) {
            return -EPERM;
        }

        ret = 0;

        // Modfy end of config should at least be protected
        // from this getting call to frequently.
        lock_config();
        if (stall_mode_enabled()) {
            // Disable stalling
            if (!arg) {
                global_config.stall_mode = 0;
                task_cache_clear();
                inode_cache_clear();
            }
        } else {
            // Enable stalling
            if (arg) {
                task_cache_clear();
                inode_cache_clear();
                global_config.stall_mode = 1;
            }
        }
        unlock_config();
        break;

    // Set Event Queue specific optimizations.
    case DYNSEC_IOC_QUEUE_OPTS: {
        struct dynsec_config new_config;

        if (!capable(CAP_SYS_ADMIN)) {
            return -EPERM;
        }
        if (!arg) {
            return -EINVAL;
        }
        if (copy_from_user(&new_config, (void *)arg, sizeof(new_config))) {
            return -EFAULT;
        }

        ret = 0;
        lock_config();
        // When enabled, notifying is much more frequent. Strictest
        // option to controlling queueing.
        if (global_config.lazy_notifier != new_config.lazy_notifier) {
            pr_info("dynsec_config: Changing lazy_notifier %u to %u",
                    global_config.lazy_notifier, new_config.lazy_notifier);
            global_config.lazy_notifier = new_config.lazy_notifier;
        }

        // Options below most noticable when lazy notifying enabled.

        // Soft limit for controlling when to notify userspace.
        // Good for controlling to many big bursts.
        if (global_config.notify_threshold != new_config.notify_threshold) {
            pr_info("dynsec_config: Changing notify_threshold %u to %u",
                    global_config.notify_threshold, new_config.notify_threshold);
            global_config.notify_threshold = new_config.notify_threshold;
        }
        // Harder limit on copying number of events to userspace per read.
        if (global_config.queue_threshold != new_config.queue_threshold) {
            pr_info("dynsec_config: Changing queue_threshold %u to %u",
                    global_config.queue_threshold, new_config.queue_threshold);
            global_config.queue_threshold = new_config.queue_threshold;
        }
        unlock_config();
        break;
    }

    case DYNSEC_IO_STALL_TIMEOUT_MS: {
        unsigned long timeout_ms = MAX_WAIT_TIMEOUT_MS;

        if (!capable(CAP_SYS_ADMIN)) {
            return -EPERM;
        }

        // 0 means it won't stall "really" stall
        // but will go through the motions.
        if (arg < MAX_WAIT_TIMEOUT_MS) {
            timeout_ms = arg;
        }

        ret = 0;
        lock_config();
        global_config.stall_timeout = timeout_ms;
        unlock_config();
        break;
    }

    default:
        break;
    }

    return ret;
}

static const struct file_operations dynsec_queue_ops = {
    .owner = THIS_MODULE,
    .write = dynsec_stall_write,
    .read = dynsec_stall_read,
    .poll = dynsec_stall_poll,
    .open = dynsec_stall_open,
    .release = dynsec_stall_release,
    .unlocked_ioctl = dynsec_stall_unlocked_ioctl,
};

void dynsec_chrdev_shutdown(void)
{
    cdev_del(&dynsec_cdev);
    unregister_chrdev_region(g_maj_t, 1);
    pr_info("%s: major: %d\n", __func__, maj_no);

    if (stall_tbl) {
        stall_tbl_shutdown(stall_tbl);
        stall_tbl = NULL;
    }
}

bool dynsec_chrdev_init(void)
{
    int ret;
    const unsigned int MINOR_FIRST = 0;

    stall_tbl = NULL;
    g_maj_t = 0;
    maj_no = 0;

    ret = alloc_chrdev_region(&g_maj_t, MINOR_FIRST, 1, CB_APP_MODULE_NAME);
    if (ret < 0){
        return false;
    }
    maj_no = MAJOR(g_maj_t);

    cdev_init(&dynsec_cdev, &dynsec_queue_ops);
    ret = cdev_add(&dynsec_cdev, g_maj_t, 1);
    if (ret < 0) {
        cdev_del(&dynsec_cdev);
        unregister_chrdev_region(g_maj_t, 1);
        return false;
    }

    pr_info("%s: major: %d\n", __func__, maj_no);
    stall_tbl = stall_tbl_alloc(GFP_KERNEL);
    if (!stall_tbl) {
        dynsec_chrdev_shutdown();
        return false;
    }

    return true;
}
