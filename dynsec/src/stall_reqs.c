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

#include "dynsec.h"
#include "stall_tbl.h"
#include "factory.h"
#include "version.h"

static dev_t g_maj_t;
static int maj_no;
static struct cdev dynsec_cdev;

struct stall_tbl *stall_tbl;


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

    if (!dynsec_event || !response || !stall_tbl_enabled(stall_tbl)) {
        free_dynsec_event(dynsec_event);
        return -EINVAL;
    }

    entry = stall_tbl_insert(stall_tbl, dynsec_event, mode);
    if (IS_ERR(entry)) {
        free_dynsec_event(dynsec_event);
        return PTR_ERR(entry);
    }

    ret = wait_event_interruptible_timeout(entry->wq, entry->mode != 0, msecs_to_jiffies(ms));
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
        stall_tbl_resume(stall_tbl, &key, DYNSEC_RESPONSE_ALLOW);
    }
    free_dynsec_event(event);

    return ret;
}

static int dynsec_stall_release(struct inode *inode, struct file *file)
{
    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }

    stall_tbl_disable(stall_tbl);

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
    ret = stall_tbl_resume(stall_tbl, &key, response.response);
    if (ret == 0) {
        ret = sizeof(response);
    }

    return ret;
}

static long dynsec_stall_unlocked_ioctl(struct file *file, unsigned int cmd,
                                        unsigned long arg)
{
    int ret = -EINVAL;

    // Check capable() on privileged commands.

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
