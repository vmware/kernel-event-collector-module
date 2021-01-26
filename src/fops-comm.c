// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <asm/uaccess.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/ioctl.h>

#include "priv.h"
#include "cb-banning.h"
#include "cb-isolation.h"
#include "hash-table-generic.h"
#include "process-tracking.h"
#include "mem-cache.h"
#include "cb-spinlock.h"

#include "InodeState.h"

const char DRIVER_NAME[] = CB_APP_MODULE_NAME;
#define MINOR_COUNT 1
ssize_t KF_LEN = sizeof(struct CB_EVENT_UM); // This needs to be sizeof(whatever we store in queue)

int ec_device_open(struct inode *inode, struct file *filep);
int ec_device_release(struct inode *inode, struct file *filep);
ssize_t ec_device_read(struct file *f, char __user *buf, size_t count, loff_t *offset);
unsigned int ec_device_poll(struct file *filep, struct poll_table_struct *poll);
long ec_device_unlocked_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
int __ec_DoAction(ProcessContext *context, uint32_t action);
void ec_user_comm_clear_queues(ProcessContext *context);
bool __ec_try_to_gain_capacity(struct list_head *tx_queue);
bool __ec_is_action_allowed(ModuleState moduleState, CB_EVENT_ACTION_TYPE action);
bool __ec_is_ioctl_allowed(ModuleState module_state, unsigned int cmd);
size_t __ec_get_memory_usage(ProcessContext *context);
void __ec_apply_legacy_driver_config(uint32_t eventFilter);
void __ec_apply_driver_config(CB_DRIVER_CONFIG *config);
char *__ec_driver_config_option_to_string(CB_CONFIG_OPTION config_option);
void __ec_print_driver_config(char *msg, CB_DRIVER_CONFIG *config);
void __ec_stats_work_task(struct work_struct *work);
void __ec_clear_tx_queue(struct list_head *tx_queue, atomic64_t *readyCount, ProcessContext *context);

// checkpatch-ignore: CONST_STRUCT
struct file_operations driver_fops = {
    .owner          = THIS_MODULE,
    .read           = ec_device_read,
    .poll           = ec_device_poll,
    .open           = ec_device_open,
    .release        = ec_device_release,
    .unlocked_ioctl = ec_device_unlocked_ioctl,
};
// checkpatch-no-ignore: CONST_STRUCT

#define  MAX_VALID_INTERVALS     60
#define  MAX_INTERVALS           62
#define  NUM_STATS               15
#define  EVENT_STATS             11
#define  MEM_START               EVENT_STATS
#define  MEM_STATS               (EVENT_STATS + 4)

typedef struct CB_EVENT_STATS {
    // This is a circular array of elements were each element is an increasing sum from the
    //  previous element. You can always get the sum of any two elements, and divide by the
    //  number of elements between them to yield the average.
    //  tx_ready;
    //  tx_dropped;
    //  tx_total;
    //  tx_other
    //  tx_process
    //  tx_modload
    //  tx_file
    //  tx_net
    //  tx_dns
    //  tx_proxy
    //  tx_block
    atomic64_t      stats[MAX_INTERVALS][NUM_STATS];
    struct timespec time[MAX_INTERVALS];

    // These are live counters that rise and fall as events are generated.  This variable
    //  will be added to the stats end the end of each interval.
    atomic64_t      tx_ready_max;
    atomic64_t      tx_ready;

    // The current index into the list
    atomic_t        curr;

    // The number of times the list has carried over. (This helps us calculate the average
    //  later by knowing how many are valid.)
    atomic_t        validStats;
} CB_EVENT_STATS, *PCB_EVENT_STATS;

const static struct {
    const char *name;
    const char *str_format;
    const char *num_format;
} STAT_STRINGS[] = {
    { "Max Queued",   " %12s ||", " %12d ||" },
    { "Dropped",        " %7s |", " %7d |" },
    { "All",            " %7s |", " %7d |" },
    { "Process",        " %7s |", " %7d |" },
    { "Modload",        " %7s |", " %7d |" },
    { "File",           " %7s |", " %7d |" },
    { "Net",            " %7s |", " %7d |" },
    { "DNS",            " %7s |", " %7d |" },
    { "Proxy",          " %7s |", " %7d |" },
    { "Blocked",        " %7s |", " %7d |" },
    { "Other",          " %7s |", " %7d |" },
    { "User",           " %10s |", " %10d |" },
    { "User Peak",      " %10s |", " %10d |" },
    { "Kernel",         " %7s |", " %7d |" },
    { "Kernel Peak",    " %12s |", " %12d |" }
};


#define current_stat        (s_fops_data.event_stats.curr)
#define valid_stats         (s_fops_data.event_stats.validStats)
#define tx_ready_max        (s_fops_data.event_stats.tx_ready_max)
#define tx_ready            (s_fops_data.event_stats.tx_ready)
#define tx_queued_max       (s_fops_data.event_stats.stats[atomic_read(&current_stat)][0])
#define tx_dropped          (s_fops_data.event_stats.stats[atomic_read(&current_stat)][1])
#define tx_total            (s_fops_data.event_stats.stats[atomic_read(&current_stat)][2])
#define tx_process          (s_fops_data.event_stats.stats[atomic_read(&current_stat)][3])
#define tx_modload          (s_fops_data.event_stats.stats[atomic_read(&current_stat)][4])
#define tx_file             (s_fops_data.event_stats.stats[atomic_read(&current_stat)][5])
#define tx_net              (s_fops_data.event_stats.stats[atomic_read(&current_stat)][6])
#define tx_dns              (s_fops_data.event_stats.stats[atomic_read(&current_stat)][7])
#define tx_proxy            (s_fops_data.event_stats.stats[atomic_read(&current_stat)][8])
#define tx_block            (s_fops_data.event_stats.stats[atomic_read(&current_stat)][9])
#define tx_other            (s_fops_data.event_stats.stats[atomic_read(&current_stat)][10])


#define mem_user            (s_fops_data.event_stats.stats[atomic_read(&current_stat)][11])
#define mem_user_peak       (s_fops_data.event_stats.stats[atomic_read(&current_stat)][12])
#define mem_kernel          (s_fops_data.event_stats.stats[atomic_read(&current_stat)][13])
#define mem_kernel_peak     (s_fops_data.event_stats.stats[atomic_read(&current_stat)][14])

static struct fops_data_t
{
    // Our device special major number
    dev_t                  major;
    struct cdev            device;
    atomic_t               reader_pid;

    struct list_head       tx_queue;

    // Flag to identify if the queue is enabled
    bool                   enabled;
    uint64_t               lock;
    struct delayed_work    stats_work;
    uint32_t               stats_work_delay;
    wait_queue_head_t      wq;

    CB_EVENT_STATS         event_stats;
} s_fops_data;

#define STAT_INTERVAL    15

void ec_reader_init(void)
{
    atomic_set(&s_fops_data.reader_pid, 0);
}

bool ec_is_reader_connected(void)
{
    return (0 != atomic_cmpxchg(&s_fops_data.reader_pid, 0, 0));
}

bool __ec_connect_reader(ProcessContext *context)
{
    return (0 == atomic_cmpxchg(&s_fops_data.reader_pid, 0, context->pid));
}

bool ec_disconnect_reader(pid_t pid)
{
    return (pid == atomic_cmpxchg(&s_fops_data.reader_pid, pid, 0));
}

bool __ec_is_process_connected_reader(pid_t pid)
{
    return (pid == atomic_cmpxchg(&s_fops_data.reader_pid, pid, pid));
}

bool ec_user_comm_initialize(ProcessContext *context)
{
    int i;
    size_t kernel_mem;

    ec_spinlock_init(&s_fops_data.lock, context);

    atomic_set(&current_stat,          0);
    atomic_set(&valid_stats,           0);
    atomic64_set(&tx_ready,            0);
    atomic64_set(&tx_ready_max,        0);

    for (i = 0; i < NUM_STATS; ++i)
    {
        // We make sure the first and last interval are 0 for the average calculations
        atomic64_set(&s_fops_data.event_stats.stats[0][i],                0);
        atomic64_set(&s_fops_data.event_stats.stats[MAX_INTERVALS - 1][i], 0);
    }
    getnstimeofday(&s_fops_data.event_stats.time[0]);
    kernel_mem = __ec_get_memory_usage(context);
    atomic64_set(&mem_kernel,      kernel_mem);
    atomic64_set(&mem_kernel_peak, kernel_mem);

    init_waitqueue_head(&s_fops_data.wq);
    INIT_LIST_HEAD(&s_fops_data.tx_queue);

    // Initialize a workque struct to police the hashtable
    s_fops_data.stats_work_delay = msecs_to_jiffies(STAT_INTERVAL * 1000);
    INIT_DELAYED_WORK(&s_fops_data.stats_work, __ec_stats_work_task);
    schedule_delayed_work(&s_fops_data.stats_work, s_fops_data.stats_work_delay);

    s_fops_data.enabled  = true;
    return true;
}

bool ec_user_devnode_init(ProcessContext *context)
{
    const unsigned int MINOR_FIRST = 0;
    int maj_no;

    // Allocate Major / Minor number of device special file
    TRY_STEP_DO(DEVNUM_ALLOC, alloc_chrdev_region(&s_fops_data.major, MINOR_FIRST, MINOR_COUNT, DRIVER_NAME) >= 0,

                TRACE(DL_ERROR, "Failed allocating character device region."););

    maj_no = MAJOR(s_fops_data.major);
    cdev_init(&s_fops_data.device, &driver_fops);
    TRY_STEP_DO(CHRDEV_ALLOC, cdev_add(&s_fops_data.device, s_fops_data.major, 1) >= 0, TRACE(DL_ERROR, "cdev_add failed"););

    s_fops_data.enabled  = true;
    return true;

CATCH_CHRDEV_ALLOC:
        unregister_chrdev_region(s_fops_data.major, MINOR_COUNT);
        cdev_del(&s_fops_data.device);

CATCH_DEVNUM_ALLOC:
    return false;
}

void ec_user_devnode_close(ProcessContext *context)
{
    cdev_del(&s_fops_data.device);
    unregister_chrdev_region(s_fops_data.major, MINOR_COUNT);
}

void ec_user_comm_early_shutdown(ProcessContext *context)
{
    // We need to disable the user comms and signal the polling process to wakeup
    s_fops_data.enabled  = false;
    ec_fops_comm_wake_up_reader(context);
}

void ec_user_comm_shutdown(ProcessContext *context)
{
    s_fops_data.enabled  = false;

    /**
     * Calling the sync flavor gives the guarantee that on the return of the
     * routine, work is not pending and not executing on any CPU.
     *
     * Its supposed to work even if the work schedules itself.
     */
    cancel_delayed_work_sync(&s_fops_data.stats_work);

    ec_user_comm_clear_queues(context);

    ec_spinlock_destroy(&s_fops_data.lock, context);
}

void ec_user_comm_clear_queues(ProcessContext *context)
{
    LIST_HEAD(local_tx_queue);

    // We only need to lock when moving the contents from the real list to our local one
    ec_write_lock(&s_fops_data.lock, context);
    list_cut_position(&local_tx_queue, &s_fops_data.tx_queue, &s_fops_data.tx_queue);
    ec_write_unlock(&s_fops_data.lock, context);

    // Clearing the queues can trigger sending an exit event. Since we're clearing the queues we don't need to send
    //  the exit events.
    DISABLE_SEND_EVENTS(context);
    __ec_clear_tx_queue(&local_tx_queue, &tx_ready, context);
    ENABLE_SEND_EVENTS(context);
}

void __ec_clear_tx_queue(struct list_head *tx_queue, atomic64_t *readyCount, ProcessContext *context)
{
    struct list_head *eventNode;
    struct list_head *safeNode;

    list_for_each_safe(eventNode, safeNode, tx_queue)
    {
        list_del(eventNode);
        ec_free_event(&(container_of(eventNode, CB_EVENT_NODE, listEntry)->data), context);
        atomic64_dec(readyCount);
    }
}

void __ec_atomic64_set_if_greater(atomic64_t *item, uint64_t new_value)
{
    while (true)
    {
        uint64_t old_value = atomic64_read(item);

        if (new_value > old_value)
        {
            // If some other thread changed the atomic value we try again
            if (atomic64_cmpxchg(item, old_value, new_value) != old_value)
            {
                continue;
            }
        }
        break;
    }
}

int ec_may_send_event(ProcessContext *context)
{
    CANCEL(s_fops_data.enabled, 0);
    CANCEL(ALLOW_SEND_EVENTS(context), 0);
    CANCEL(ec_is_reader_connected(), 0);

    CANCEL_DO(atomic64_read(&tx_ready) < g_max_queue_size, 0, {
        atomic64_inc(&tx_dropped);
    });

    // If we get past the tests above we are safe to send
    return 1;
}

int ec_send_event(struct CB_EVENT *msg, ProcessContext *context)
{
    int                result     = -1;
    uint64_t           readyCount = 0;
    CB_EVENT_NODE     *eventNode = container_of(msg, CB_EVENT_NODE, data);

    TRY(msg);
    TRY(s_fops_data.enabled);
    TRY(ALLOW_SEND_EVENTS(context));
    TRY(ec_is_reader_connected());

    ec_write_lock(&s_fops_data.lock, context);
    list_add_tail(&(eventNode->listEntry), &s_fops_data.tx_queue);
    ec_write_unlock(&s_fops_data.lock, context);

    readyCount = atomic64_inc_return(&tx_ready);
    TRACE(DL_VERBOSE, "send_event_atomic %p %llu", msg, readyCount);
    msg = NULL;

    // Possibly update the tx_ready_max if this is the most events queued for this interval
    __ec_atomic64_set_if_greater(&tx_ready_max, readyCount);

    // Wake up the reader task if we are allowed to
    ec_fops_comm_wake_up_reader(context);
    result = 0;

CATCH_DEFAULT:
    if (msg)
    {
        // If we still have an event at this point free it now
        atomic64_inc(&tx_dropped);
        TRACE(DL_INFO, "Failed event insertion");
        ec_free_event(msg, context);
    }

    return result;
}

void ec_fops_comm_wake_up_reader(ProcessContext *context)
{
    // Wake up the reader task if we are allowed to
    if (ALLOW_WAKE_UP(context))
    {
        wake_up(&s_fops_data.wq);
    }
}

ssize_t ec_device_read(struct file *f,  char __user *ubuf, size_t count, loff_t *offset)
{
    struct CB_EVENT      *msg        = NULL;
    struct CB_EVENT_UM   *msg_user   = (struct CB_EVENT_UM *)ubuf;
    int                   rc         = 0;
    ssize_t               len        = 0;
    uint64_t              readyCount = atomic64_read(&tx_ready);
    int                   xcode      = -ENOMEM;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    TRACE(DL_COMMS, "%s: start read", __func__);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // You *must* ask for at least 1 packet

    TRY_DO_MSG(count >= KF_LEN,
               { xcode = -ENOMEM; },
               DL_COMMS, "%s: size mismatch count=%ld KF_LEN=%ld", __func__, count, KF_LEN);

    TRY_DO_MSG(readyCount > 0,
                { xcode = -ENOMEM; },
                DL_COMMS,
                "%s: empty queue", __func__);

    {
        CB_EVENT_NODE *eventNode = NULL;

        ec_write_lock(&s_fops_data.lock, &context);
        eventNode = list_first_entry_or_null(&s_fops_data.tx_queue, CB_EVENT_NODE, listEntry);
        if (eventNode)
        {
            list_del(&eventNode->listEntry);
        }
        ec_write_unlock(&s_fops_data.lock, &context);

        if (eventNode)
        {
            msg = &eventNode->data;
            atomic64_dec(&tx_ready);
        }
    }

    TRY_DO_MSG(msg,
               { xcode = -ENOMEM; },
               DL_COMMS,
               "%s: failed to dequeue event", __func__);

    // Write the process path to user memory (if it exists)
    //  This happens before the main event so that we can clear out the pointer value in the event before writing it
    if (msg->procInfo.path)
    {
        len = min_t(size_t, ec_mem_cache_get_size_generic(msg->procInfo.path), (size_t) PATH_MAX);
        rc  = copy_to_user((void *) &msg_user->proc_path.data, msg->procInfo.path, len);
        TRY_STEP(COPY_FAIL, !rc);

        rc = put_user(len, &msg_user->proc_path.size);
        TRY_STEP(COPY_FAIL, !rc);
    }

    if (msg->generic_data.data)
    {
        len = min_t(size_t, ec_mem_cache_get_size_generic(msg->generic_data.data), (size_t) PATH_MAX);
        rc  = copy_to_user((void *) &msg_user->event_data.data, msg->generic_data.data, len);
        TRY_STEP(COPY_FAIL, !rc);

        rc = put_user(len, &msg_user->event_data.size);
        TRY_STEP(COPY_FAIL, !rc);
    }

    // Write the main event to user
    rc = copy_to_user((void *)&msg_user->event, msg, sizeof(struct CB_EVENT));
    TRY_STEP(COPY_FAIL, !rc);

    // Clear the two pointer values because they are not valid
    rc = put_user(0, &msg_user->event.procInfo.path);
    TRY_STEP(COPY_FAIL, !rc);

    rc = put_user(0, &msg_user->event.generic_data.data);
    TRY_STEP(COPY_FAIL, !rc);

    atomic64_inc(&tx_total);

    switch (msg->eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START:
    case CB_EVENT_TYPE_PROCESS_EXIT:
        atomic64_inc(&tx_process);
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
        atomic64_inc(&tx_modload);
        break;

    case CB_EVENT_TYPE_FILE_CREATE:
    case CB_EVENT_TYPE_FILE_DELETE:
    case CB_EVENT_TYPE_FILE_WRITE:
    case CB_EVENT_TYPE_FILE_CLOSE:
    case CB_EVENT_TYPE_FILE_OPEN:
        atomic64_inc(&tx_file);
        break;

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
    case CB_EVENT_TYPE_NET_CONNECT_POST:
    case CB_EVENT_TYPE_NET_ACCEPT:
        atomic64_inc(&tx_net);
        break;

    case CB_EVENT_TYPE_DNS_RESPONSE:
        atomic64_inc(&tx_dns);
        break;

    case CB_EVENT_TYPE_WEB_PROXY:
        atomic64_inc(&tx_proxy);
        break;

    case CB_EVENT_TYPE_PROCESS_BLOCKED:
    case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
        atomic64_inc(&tx_block);
        break;

    case CB_EVENT_TYPE_PROC_ANALYZE:
    case CB_EVENT_TYPE_HEARTBEAT:
    case CB_EVENT_TYPE_MAX:
    case CB_EVENT_TYPE_UNKNOWN:
    default:
        atomic64_inc(&tx_other);
        break;
    }

CATCH_COPY_FAIL:
    // Check the result
    if (rc)
    {
        TRACE(DL_ERROR, "%s: copy to user failed rc=%d", __func__, rc);
        xcode = -ENXIO;
    } else
    {
        *offset = 0;
        xcode = KF_LEN;
        TRACE(DL_COMMS, "%s: read=%ld qlen=%lluu", __func__, len, readyCount);
    }

CATCH_DEFAULT:
    ec_free_event(msg, &context);
    FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

int ec_device_open(struct inode *inode, struct file *filp)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    TRACE(DL_INFO, "%s: attempting to connect to device from pid[%d]", __func__, context.pid);

    if (!__ec_connect_reader(&context))
    {
        // The ec_device_release call is called asynchronously from the reader closing
        //  the device.  The test-app rapidly closes and reopens the device.
        //  Occasionally the reopen occurs before the cleanup, and it fails (4%).
        // This brief sleep allows us to recheck in this case, and possibly still
        //  connect.
        usleep_range(10000, 11000);
        if (!__ec_connect_reader(&context))
        {
            TRACE(DL_WARNING, "%s: refusing connection to device from pid[%d]; only one connection is allowed", __func__, context.pid);
            return -ECONNREFUSED;
        }
    }

    TRACE(DL_INFO, "%s: connected to device from pid[%d]", __func__, context.pid);

    return nonseekable_open(inode, filp);
}

int ec_device_release(struct inode *inode, struct file *filp)
{
    TRACE(DL_INFO, "%s: releasing device from pid[%d]; s_fops_data.reader_pid[%d]", __func__, ec_getpid(current), atomic_read(&s_fops_data.reader_pid));

    if (!ec_disconnect_reader(ec_getpid(current)))
    {
        return -ECONNREFUSED;
    }

    return 0;
}

unsigned int ec_device_poll(struct file *filp, struct poll_table_struct *pts)
{
    int      xcode = 0;
    uint64_t qlen  = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Check if data is available.  If data is ready we can exit now.  Otherwise wait.
    qlen = atomic64_read(&tx_ready);
    TRY_MSG(qlen == 0, DL_COMMS, "%s: msg available qlen=%llu", __func__, qlen);

    // We should call poll_wait here if we want the kernel to actually
    // sleep when waiting for us.
    TRACE(DL_COMMS, "%s: waiting for data", __func__);
    poll_wait(filp, &s_fops_data.wq, pts);

    qlen = atomic64_read(&tx_ready);
    TRACE(DL_COMMS, "%s: msg available qlen=%llu", __func__, qlen);

CATCH_DEFAULT:
    // If comms have been disabled while we were waiting send POLLHUP
    if (!s_fops_data.enabled)
    {
        xcode = POLLHUP;
    } else
    {
        // Report if we have events to read
        xcode = qlen != 0 ? (POLLIN | POLLRDNORM) : 0;
    }

    FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}


long ec_device_unlocked_ioctl(struct file *filep, unsigned int cmd_in, unsigned long arg)
{
    unsigned int cmd  = _IOC_NR(cmd_in);
    size_t       size = _IOC_SIZE(cmd_in);
    void *page = 0;
    union {
        uint32_t         value;
        CB_EVENT_DYNAMIC dynControl;
        CB_DRIVER_CONFIG config;
        unsigned char    raw[0];
    } data;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    /**
     * If the module is disabled cannot process any commands.
     * The only allowed command is enable.
     */

    ModuleState moduleState = ec_get_module_state(&context);

    TRACE(DL_INFO, "%s: ioctl from pid[%d]", __func__, context.pid);

    // Only the connected process can send ioctls to this kernel module.
    if (!__ec_is_process_connected_reader(context.pid))
    {
        TRACE(DL_ERROR, "%s: Cannot process cmd=%d, process not authorized; pid[%d], reader-pid[%d]", __func__, cmd, context.pid, atomic_read(&s_fops_data.reader_pid));
        return -EPERM;
    }

    if (!arg)
    {
        TRACE(DL_ERROR, "%s: arg null", __func__);
        return -ENOMEM;
    }

    if (!__ec_is_ioctl_allowed(moduleState, cmd))
    {
        TRACE(DL_ERROR, "%s: Cannot process cmd=%d, module is not enabled", __func__, cmd);
        return -EPERM;
    }

    if ((cmd == CB_DRIVER_REQUEST_SET_BANNED_INODE) ||
        (cmd == CB_DRIVER_REQUEST_SET_BANNED_INODE_WITHOUT_KILL) ||
        (cmd == CB_DRIVER_REQUEST_CLR_BANNED_INODE) ||
        (cmd == CB_DRIVER_REQUEST_SET_TRUSTED_PATH))
    {
        page = (void *)__get_free_page(GFP_MODE(&context));
        if (!page)
        {
            TRACE(DL_ERROR, "%s: alloc failed cmd=%d", __func__, cmd);
            return -ENOMEM;
        }
    } else
    {
        if (copy_from_user((void *)data.raw, (void *)arg, min(sizeof(data), size)))
        {
            TRACE(DL_ERROR, "%s: failed to copy arg", __func__);
            return -ENOMEM;
        }
    }

    switch (cmd)
    {
    case CB_DRIVER_REQUEST_APPLY_FILTER:
        {
            __ec_apply_legacy_driver_config(data.value);
        }
        break;

    case CB_DRIVER_REQUEST_CONFIG:
        {
            __ec_apply_driver_config(&data.config);
        }
        break;

    case CB_DRIVER_REQUEST_IGNORE_UID:
        {
            uid_t uid = (uid_t)data.value;

            TRACE(DL_INFO, "Received uid=%u", uid);
            ec_banning_SetIgnoredUid(&context, uid);
        }
        break;

    case CB_DRIVER_REQUEST_IGNORE_SERVER:
        {
            uid_t uid = (uid_t)data.value;

            TRACE(DL_INFO, "Recevied server uid curr=%u new%u", uid,  g_edr_server_uid);
            if (uid != g_edr_server_uid)
            {
                TRACE(DL_WARNING, "+Setting CB server UID=%u", uid);
                g_edr_server_uid  = uid;
            }
        }
        break;

    case CB_DRIVER_REQUEST_IGNORE_PID:
        {
            pid_t pid = (pid_t)data.value;

            TRACE(DL_INFO, "Recevied trusted pid=%u", pid);
            ec_banning_SetIgnoredProcess(&context, pid);
        }
        break;

    case CB_DRIVER_REQUEST_ISOLATION_MODE_CONTROL:
        {
            ec_ProcessIsolationIoctl(&context, IOCTL_SET_ISOLATION_MODE, (void *)data.dynControl.data, data.dynControl.size);
        }
        break;

    case CB_DRIVER_REQUEST_HEARTBEAT:
        {
            PCB_EVENT event = NULL;

            CB_EVENT_HEARTBEAT heartbeat;

            if (copy_from_user(&heartbeat, (void *)arg, sizeof(heartbeat)))
            {
                TRACE(DL_ERROR, "%s: failed to copy arg", __func__);
                return -ENOMEM;
            }

            TRACE(DL_INFO, "Got a heartbeat request.");
            event = ec_alloc_event(CB_EVENT_TYPE_HEARTBEAT, &context);
            if (event == NULL)
            {
                TRACE(DL_ERROR, "Unable to alloc CB_EVENT_TYPE_HEARTBEAT.");
            } else
            {
                atomic64_set(&mem_user,      heartbeat.user_memory);
                atomic64_set(&mem_user_peak, heartbeat.user_memory_peak);
                event->heartbeat.user_memory        = heartbeat.user_memory;
                event->heartbeat.user_memory_peak   = heartbeat.user_memory_peak;
                event->heartbeat.kernel_memory      = atomic64_read(&mem_kernel);
                event->heartbeat.kernel_memory_peak = atomic64_read(&mem_kernel_peak);
                ec_send_event(event, &context);
            }
        }
        break;

    case CB_DRIVER_REQUEST_SET_BANNED_INODE:
        {
            PCB_PROTECTION_CONTROL protectionData = (PCB_PROTECTION_CONTROL)page;
            int i;

            if (copy_from_user(page, (void *)arg, sizeof(CB_PROTECTION_CONTROL)))
            {
                TRACE(DL_ERROR, "%s: failed to copy arg", __func__);
                free_page((unsigned long)page);
                return -ENOMEM;
            }

            for (i = 0; i < protectionData->count; ++i)
            {
                if (protectionData->data[i].action == InodeBanned)
                {
                    ec_banning_SetBannedProcessInode(&context, protectionData->data[i].device, protectionData->data[i].inode);
                    TRACE(DL_INFO, "%s: banned inode: [%llu:%llu]", __func__, protectionData->data[i].device, protectionData->data[i].inode);
                }
            }
            free_page((unsigned long)page);
        }
        break;

    case CB_DRIVER_REQUEST_SET_BANNED_INODE_WITHOUT_KILL:
        {
            PCB_PROTECTION_CONTROL protectionData = (PCB_PROTECTION_CONTROL)page;
            int i;

            if (copy_from_user(page, (void *)arg, sizeof(CB_PROTECTION_CONTROL)))
            {
                TRACE(DL_ERROR, "%s: failed to copy arg", __func__);
                free_page((unsigned long)page);
                return -ENOMEM;
            }

            for (i = 0; i < protectionData->count; i++)
            {
                if (protectionData->data[i].action == InodeBanned)
                {
                    ec_banning_SetBannedProcessInodeWithoutKillingProcs(&context, protectionData->data[i].device, protectionData->data[i].inode);
                    TRACE(DL_INFO, "%s: banned inode (w/o proc kill): [%llu:%llu]",
                          __func__, protectionData->data[i].device, protectionData->data[i].inode);
                }
            }
            free_page((unsigned long)page);
        }
        break;

    case CB_DRIVER_REQUEST_PROTECTION_ENABLED:
        {
            ec_banning_SetProtectionState(&context, (uint32_t)data.value);
        }

    case CB_DRIVER_REQUEST_CLR_BANNED_INODE:
        {
            ec_banning_ClearAllBans(&context);
            free_page((unsigned long)page);
        }
        break;

    case CB_DRIVER_REQUEST_SET_TRUSTED_PATH:
        {
            PCB_TRUSTED_PATH pathData = (PCB_TRUSTED_PATH)page;

            if (copy_from_user(page, (void *)arg, size))
            {
                TRACE(DL_ERROR, "%s: failed to copy arg", __func__);
                free_page((unsigned long)page);
                return -ENOMEM;
            }

            TRACE(DL_INFO, "pathData=%p path=%s", pathData, pathData->path);
            free_page((unsigned long)page);
        }
        break;

    case CB_DRIVER_REQUEST_SET_LOG_LEVEL:
        {
            g_traceLevel = data.value;
            TRACE(DL_INFO, "Set trace level=%x", g_traceLevel);
        }
        break;

    case CB_DRIVER_REQUEST_ACTION:
        {
            int result = 0;
            CB_EVENT_ACTION_TYPE action = (CB_EVENT_ACTION_TYPE) data.value;

            if (!__ec_is_action_allowed(moduleState, action))
            {
                TRACE(DL_ERROR, "%s: Module state is %d, cmd %d, action %d is illegal", __func__, moduleState, cmd, action);
                return -EPERM;
            }

            result = __ec_DoAction(&context, action);
            return result;
        }
        break;

    default:
        TRACE(DL_INFO, "Unknown request type %d", cmd);
        break;
    }

    return 0l;
}


bool __ec_is_ioctl_allowed(ModuleState module_state, unsigned int cmd)
{
    return (module_state == ModuleStateEnabled || cmd == CB_DRIVER_REQUEST_ACTION);
}

/**
 * Check if module is not enabled, the only allowed action is one that changes states,
 * fail any other actions.
 */
bool __ec_is_action_allowed(ModuleState moduleState, CB_EVENT_ACTION_TYPE action)
{
    return ((moduleState == ModuleStateEnabled) ||
            (action == CB_EVENT_ACTION_ENABLE_EVENT_COLLECTOR ||
             action == CB_EVENT_ACTION_DISABLE_EVENT_COLLECTOR));
}

int __ec_DoAction(ProcessContext *context, CB_EVENT_ACTION_TYPE action)
{
    int result = 0;

    TRACE(DL_INFO, "Recevied action=%u", action);
    switch (action)
    {
    case CB_EVENT_ACTION_CLEAR_EVENT_QUEUE:
        ec_user_comm_clear_queues(context);
        break;

    case CB_EVENT_ACTION_ENABLE_EVENT_COLLECTOR:
        result = ec_enable_module(context);
        break;

    case CB_EVENT_ACTION_DISABLE_EVENT_COLLECTOR:
        result = ec_disable_module(context);
        break;

    case CB_EVENT_ACTION_REQUEST_PROCESS_DISCOVERY:
        ec_process_tracking_send_process_discovery(context);
        break;

    default:
        break;
    }

    return result;
}

void __ec_apply_legacy_driver_config(uint32_t eventFilter)
{
    g_driver_config.processes = (eventFilter & CB_EVENT_FILTER_PROCESSES ? ALL_FORKS_AND_EXITS : DISABLE);
    g_driver_config.module_loads = (eventFilter & CB_EVENT_FILTER_MODULE_LOADS ? ENABLE : DISABLE);
    g_driver_config.file_mods = (eventFilter & CB_EVENT_FILTER_FILEMODS ? ENABLE : DISABLE);
    g_driver_config.net_conns = (eventFilter & CB_EVENT_FILTER_NETCONNS ? ENABLE : DISABLE);
    g_driver_config.report_process_user = (eventFilter & CB_EVENT_FILTER_PROCESSUSER ? ENABLE : DISABLE);

    __ec_print_driver_config("New Module Config", &g_driver_config);
}

void __ec_apply_driver_config(CB_DRIVER_CONFIG *config)
{
    if (config)
    {
        g_driver_config.processes = (config->processes != NO_CHANGE ? config->processes : g_driver_config.processes);
        g_driver_config.module_loads = (config->module_loads != NO_CHANGE ? config->module_loads : g_driver_config.module_loads);
        g_driver_config.file_mods = (config->file_mods != NO_CHANGE ? config->file_mods : g_driver_config.file_mods);
        g_driver_config.net_conns = (config->net_conns != NO_CHANGE ? config->net_conns : g_driver_config.net_conns);
        g_driver_config.report_process_user = (config->report_process_user != NO_CHANGE ? config->report_process_user : g_driver_config.report_process_user);

        __ec_print_driver_config("New Module Config", &g_driver_config);
    }
}

#define STR(A) #A

char *__ec_driver_config_option_to_string(CB_CONFIG_OPTION config_option)
{
    char *str =  "<unknown>";

    switch (config_option)
    {
    case NO_CHANGE: str = STR(NO_CHANGE); break;
    case DISABLE: str = STR(DISABLE); break;
    case ENABLE: str = STR(ENABLE); break;
    case ALL_FORKS_AND_EXITS: str = STR(ALL_FORKS_AND_EXITS); break;
    case EXECS_ONLY: str = STR(EXECS_ONLY); break;
    case COLLAPSED_EXITS_ALL_FORKS: str = STR(COLLAPSED_EXITS_ALL_FORKS); break;
    case COLLAPSED_EXITS_NO_FORKS: str = STR(COLLAPSED_EXITS_NO_FORKS); break;
    }
    return str;
}

void __ec_print_driver_config(char *msg, CB_DRIVER_CONFIG *config)
{
    if (config)
    {
        TRACE(DL_INFO, "%s: %s, %s, %s, %s, %s",
            msg,
            __ec_driver_config_option_to_string(config->processes),
            __ec_driver_config_option_to_string(config->module_loads),
            __ec_driver_config_option_to_string(config->file_mods),
            __ec_driver_config_option_to_string(config->net_conns),
            __ec_driver_config_option_to_string(config->report_process_user));
    }
}

void __ec_stats_work_task(struct work_struct *work)
{
    uint32_t         curr   = atomic_read(&current_stat);
    uint32_t         next   = (curr + 1) % MAX_INTERVALS;
    int              i;
    size_t           kernel_mem;
    size_t           kernel_mem_peak;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    // I am not strictly speaking doing this operation atomicly.  This means there is a
    //  chance that a counter will be missed.  I am willing to allow that for the sake of
    //  performance.

    // tx_ready_max is a live counters that is set for each interval.
    //   Clear tx_ready_max and set the current value at the same time
    atomic64_add(atomic64_xchg(&tx_ready_max, 0), &tx_queued_max);

    // Copy over the current total to the next interval
    for (i = 0; i < NUM_STATS; ++i)
    {
        atomic64_set(&s_fops_data.event_stats.stats[next][i], atomic64_read(&s_fops_data.event_stats.stats[curr][i]));
    }
    atomic_set(&current_stat, next);
    atomic_inc(&valid_stats);
    getnstimeofday(&s_fops_data.event_stats.time[next]);
    kernel_mem      = __ec_get_memory_usage(&context);
    kernel_mem_peak = atomic64_read(&mem_kernel_peak);
    atomic64_set(&mem_kernel,      kernel_mem);
    atomic64_set(&mem_kernel_peak, (kernel_mem > kernel_mem_peak ? kernel_mem : kernel_mem_peak));

    schedule_delayed_work(&s_fops_data.stats_work, s_fops_data.stats_work_delay);
}

// Print event stats
int ec_proc_show_events_avg(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    // Back the current pointer to the last valid
    uint32_t    _curr   = atomic_read(&current_stat) + MAX_INTERVALS - 1;
    uint32_t    curr    = _curr % MAX_INTERVALS;
    uint32_t    valid   = atomic_read(&valid_stats);
    int32_t     avg1_c  = (valid >  4 ?  4 : valid);
    int32_t     avg2_c  = (valid > 20 ? 20 : valid);
    int32_t     avg3_c  = (valid > 60 ? 60 : valid);
    int32_t     avg1    = (_curr - avg1_c) % MAX_INTERVALS;
    int32_t     avg2    = (_curr - avg2_c) % MAX_INTERVALS;
    int32_t     avg3    = (_curr - avg3_c) % MAX_INTERVALS;

    int         i;

    if (valid == 0)
    {
        seq_puts(m, "No Data\n");
        return 0;
    }

    seq_printf(m, " %15s | %9s | %9s | %9s | %10s |\n", "Stat", "Total",  "1 min avg", "5 min avg", "15 min avg");

    // Uncomment this to debug the averaging
    //seq_printf(m, " %15s | %9d | %9d | %9d | %10d\n", "Avgs", curr, avg1, avg2, avg3 );

    // This group reports the average value for the interval
    for (i = 0; i < 1; ++i)
    {
        // This is a circular array of elements were each element is an increasing sum from the
        //  previous element. You can always get the difference of any two elements, and divide by the
        //  number of elements between them to yield the average.
        uint64_t currentStat = atomic64_read(&s_fops_data.event_stats.stats[curr][i]);

        seq_printf(m, " %15s | %9lld | %9lld | %9lld | %10lld |\n", STAT_STRINGS[i].name, currentStat,
                   (currentStat - atomic64_read(&s_fops_data.event_stats.stats[avg1][i])) / avg1_c,
                   (currentStat - atomic64_read(&s_fops_data.event_stats.stats[avg2][i])) / avg2_c,
                   (currentStat - atomic64_read(&s_fops_data.event_stats.stats[avg3][i])) / avg3_c);
    }

    // This group reports the average per second
    for (i = 1; i < EVENT_STATS; ++i)
    {
        // This is a circular array of elements were each element is an increasing sum from the
        //  previous element. You can always get the difference of any two elements, and divide by the
        //  number of elements between them to yield the average.
        uint64_t currentStat = atomic64_read(&s_fops_data.event_stats.stats[curr][i]);

        seq_printf(m, " %15s | %9lld | %9lld | %9lld | %10lld |\n", STAT_STRINGS[i].name, currentStat,
                   (currentStat - atomic64_read(&s_fops_data.event_stats.stats[avg1][i])) / avg1_c / STAT_INTERVAL,
                   (currentStat - atomic64_read(&s_fops_data.event_stats.stats[avg2][i])) / avg2_c / STAT_INTERVAL,
                   (currentStat - atomic64_read(&s_fops_data.event_stats.stats[avg3][i])) / avg3_c / STAT_INTERVAL);
    }

    seq_puts(m, "\n");

    return 0;
}

int ec_proc_show_events_det(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = atomic_read(&current_stat);
    uint32_t    valid   = min(atomic_read(&valid_stats), MAX_VALID_INTERVALS);
    uint32_t    start   = (MAX_INTERVALS + curr - valid) % MAX_INTERVALS + MAX_INTERVALS;
    int         i;
    int         j;

    if (valid == 0)
    {
        seq_puts(m, "No Data\n");
        return 0;
    }
    //seq_printf(m, "Curr = %d, valid = %d, start = %d\n", curr, valid, start - MAX_INTERVALS );

    seq_printf(m, " %19s |", "Timestamp");
    for (j = 0; j < EVENT_STATS; ++j)
    {
        seq_printf(m, STAT_STRINGS[j].str_format, STAT_STRINGS[j].name);
    }
    seq_puts(m, "\n");

    for (i = 0; i < valid; ++i)
    {
        uint64_t left  = (start + i - 1) % MAX_INTERVALS;
        uint64_t right = (start + i) % MAX_INTERVALS;

        seq_printf(m, " %19lld |", ec_to_windows_timestamp(&s_fops_data.event_stats.time[right]));
        for (j = 0; j < EVENT_STATS; ++j)
        {
            seq_printf(m, STAT_STRINGS[j].num_format, atomic64_read(&s_fops_data.event_stats.stats[right][j]) - atomic64_read(&s_fops_data.event_stats.stats[left][j]));
        }
        seq_puts(m, "\n");
    }

    return 0;
}

ssize_t ec_proc_show_events_rst(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    int i;

    // Cancel the currently scheduled job
    cancel_delayed_work(&s_fops_data.stats_work);

    // I do not need to zero out everything, just the new active interval
    atomic_set(&current_stat,  0);
    atomic_set(&valid_stats,   0);
    for (i = 0; i < NUM_STATS; ++i)
    {
        // We make sure the first and last interval are 0 for the average calculations
        atomic64_set(&s_fops_data.event_stats.stats[0][i],                0);
        atomic64_set(&s_fops_data.event_stats.stats[MAX_INTERVALS - 1][i], 0);
    }
    getnstimeofday(&s_fops_data.event_stats.time[0]);

    // Resatrt the job from now
    schedule_delayed_work(&s_fops_data.stats_work, s_fops_data.stats_work_delay);
    return size;
}

int ec_proc_current_memory_avg(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = atomic_read(&current_stat);

    int         i;

    for (i = MEM_START; i < MEM_STATS; ++i)
    {
        // This is a circular array of elements were each element is an increasing sum from the
        //  previous element. You can always get the sum of any two elements, and divide by the
        //  number of elements between them to yield the average.
        uint64_t currentStat = atomic64_read(&s_fops_data.event_stats.stats[curr][i]);

        seq_printf(m, "%9lld ", currentStat);
    }

    seq_puts(m, "\n");

    return 0;
}

int ec_proc_current_memory_det(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = atomic_read(&current_stat);
    uint32_t    valid   = min(atomic_read(&valid_stats), MAX_VALID_INTERVALS);
    uint32_t    start   = (MAX_INTERVALS + curr - valid) % MAX_INTERVALS + MAX_INTERVALS;
    int         i;
    int         j;

    if (valid == 0)
    {
        seq_puts(m, "No Data\n");
        return 0;
    }
    //seq_printf(m, "Curr = %d, valid = %d, start = %d\n", curr, valid, start - MAX_INTERVALS );

    seq_printf(m, " %19s |", "Timestamp");
    for (j = MEM_START; j < MEM_STATS; ++j)
    {
        seq_printf(m, STAT_STRINGS[j].str_format, STAT_STRINGS[j].name);
    }
    seq_puts(m, "\n");

    for (i = 0; i < valid; ++i)
    {
        uint64_t right = (start + i) % MAX_INTERVALS;

        seq_printf(m, " %19lld |", ec_to_windows_timestamp(&s_fops_data.event_stats.time[right]));
        for (j = MEM_START; j < MEM_STATS; ++j)
        {
            seq_printf(m, STAT_STRINGS[j].num_format, atomic64_read(&s_fops_data.event_stats.stats[right][j]));
        }
        //seq_printf(m, " %9lld | %9lld |", left, right );
        seq_puts(m, "\n");
    }

    return 0;
}

size_t __ec_get_memory_usage(ProcessContext *context)
{
    return ec_mem_cache_get_memory_usage(context) +
           ec_hashtbl_get_memory(context);
}
