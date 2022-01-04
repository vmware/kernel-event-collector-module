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
#include "hash-table.h"
#include "process-tracking.h"
#include "mem-alloc.h"
#include "cb-spinlock.h"
#include "netfilter.h"
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
void ec_user_comm_clear_queue(ProcessContext *context);
bool __ec_is_action_allowed(ModuleState moduleState, CB_EVENT_ACTION_TYPE action);
bool __ec_is_ioctl_allowed(ModuleState module_state, unsigned int cmd);
size_t __ec_get_memory_usage(ProcessContext *context);
void __ec_apply_legacy_driver_config(uint32_t eventFilter);
void __ec_apply_driver_config(CB_DRIVER_CONFIG *config);
char *__ec_driver_config_option_to_string(CB_CONFIG_OPTION config_option);
void __ec_print_driver_config(char *msg, CB_DRIVER_CONFIG *config);
void __ec_transfer_from_input_queue(void);
int __ec_copy_cbevent_to_user(char __user *ubuf, size_t count, ProcessContext *context);
int __ec_precompute_payload(struct CB_EVENT *cb_event);
void __ec_stats_work_task(struct work_struct *work);

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

static LIST_HEAD(msg_queue);

static LLIST_HEAD(msg_queue_in);

static const uint64_t MAX_VALID_INTERVALS =   60;
#define  MAX_INTERVALS           62
#define  NUM_STATS               15
#define  EVENT_STATS             10
#define  MEM_START               EVENT_STATS
#define  MEM_STATS               (EVENT_STATS + 4)


typedef struct CB_EVENT_STATS {
    // This is a circular array of elements were each element is an increasing sum from the
    //  previous element. You can always get the sum of any two elements, and divide by the
    //  number of elements between them to yield the average.
    //  tx_queued_t;
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
    uint64_t        stats[MAX_INTERVALS][NUM_STATS];
    struct timespec time[MAX_INTERVALS];

    // This tracks the number of events currently queued.  This variable
    //  will be added to the stats at the end of each interval.
    struct percpu_counter tx_ready;

    // The current index into the list
    uint64_t        curr;

    // The number of times the list has carried over. (This helps us calculate the average
    //  later by knowing how many are valid.)
    uint64_t        validStats;
} CB_EVENT_STATS, *PCB_EVENT_STATS;

const static struct {
    const char *name;
    const char *str_format;
    const char *num_format;
} STAT_STRINGS[] = {
    { "Total Queued",   " %12s ||", " %12d ||" },
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
#define tx_ready            (s_fops_data.event_stats.tx_ready)
#define tx_queued_t         (s_fops_data.event_stats.stats[current_stat][0])
#define tx_dropped          (s_fops_data.event_stats.stats[current_stat][1])
#define tx_total            (s_fops_data.event_stats.stats[current_stat][2])
#define tx_process          (s_fops_data.event_stats.stats[current_stat][3])
#define tx_modload          (s_fops_data.event_stats.stats[current_stat][4])
#define tx_file             (s_fops_data.event_stats.stats[current_stat][5])
#define tx_net              (s_fops_data.event_stats.stats[current_stat][6])
#define tx_dns              (s_fops_data.event_stats.stats[current_stat][7])
#define tx_proxy            (s_fops_data.event_stats.stats[current_stat][8])
#define tx_block            (s_fops_data.event_stats.stats[current_stat][9])
#define tx_other            (s_fops_data.event_stats.stats[current_stat][10])

#define mem_user            (s_fops_data.event_stats.stats[current_stat][11])
#define mem_user_peak       (s_fops_data.event_stats.stats[current_stat][12])
#define mem_kernel          (s_fops_data.event_stats.stats[current_stat][13])
#define mem_kernel_peak     (s_fops_data.event_stats.stats[current_stat][14])

static struct  fops_config_t
{
    // Our device special major number
    dev_t                  major;
    struct cdev            device;
    pid_t                  reader_pid;

    // Flag to identify if the queue is enabled
    bool                   enabled;
    struct delayed_work    stats_work;
    uint32_t               stats_work_delay;
    wait_queue_head_t      wq;
    bool                   need_wakeup;
} s_fops_config __read_mostly;

static struct fops_data_t
{
    CB_EVENT_STATS         event_stats;
} s_fops_data;

#define STAT_INTERVAL    15

bool ec_reader_init(ProcessContext *context)
{
    s_fops_config.reader_pid = 0;
    return true;
}

bool ec_is_reader_connected(void)
{
    return s_fops_config.reader_pid != 0;
}

bool __ec_connect_reader(ProcessContext *context)
{
    if (s_fops_config.reader_pid)
    {
        return false;
    }

    s_fops_config.reader_pid = context->pid;
    return true;
}

bool ec_disconnect_reader(pid_t pid)
{
    if (s_fops_config.reader_pid != pid)
    {
        return false;
    }

    s_fops_config.reader_pid = 0;
    return true;
}

bool __ec_is_process_connected_reader(pid_t pid)
{
    return s_fops_config.reader_pid == pid;
}

bool ec_user_comm_initialize(ProcessContext *context)
{
    size_t kernel_mem;

    current_stat = 0;
    valid_stats  = 0;
    ec_percpu_counter_init(&tx_ready, 0, GFP_MODE(context));

    memset(&s_fops_data.event_stats.stats, 0, sizeof(s_fops_data.event_stats.stats));

    getnstimeofday(&s_fops_data.event_stats.time[0]);
    kernel_mem = __ec_get_memory_usage(context);
    mem_kernel =      kernel_mem;
    mem_kernel_peak = kernel_mem;

    s_fops_config.need_wakeup = true;
    init_waitqueue_head(&s_fops_config.wq);

    // Initialize a workque struct to police the hashtable
    s_fops_config.stats_work_delay = msecs_to_jiffies(STAT_INTERVAL * 1000);
    INIT_DELAYED_WORK(&s_fops_config.stats_work, __ec_stats_work_task);
    schedule_delayed_work(&s_fops_config.stats_work, s_fops_config.stats_work_delay);

    return true;
}

bool ec_user_devnode_init(ProcessContext *context)
{
    const unsigned int MINOR_FIRST = 0;
    int maj_no;

    // Allocate Major / Minor number of device special file
    TRY_STEP_DO(DEVNUM_ALLOC, alloc_chrdev_region(&s_fops_config.major, MINOR_FIRST, MINOR_COUNT, DRIVER_NAME) >= 0,

                TRACE(DL_ERROR, "Failed allocating character device region."););

    maj_no = MAJOR(s_fops_config.major);
    cdev_init(&s_fops_config.device, &driver_fops);
    TRY_STEP_DO(CHRDEV_ALLOC, cdev_add(&s_fops_config.device, s_fops_config.major, 1) >= 0, TRACE(DL_ERROR, "cdev_add failed"););

    return true;

CATCH_CHRDEV_ALLOC:
        unregister_chrdev_region(s_fops_config.major, MINOR_COUNT);
        cdev_del(&s_fops_config.device);

CATCH_DEVNUM_ALLOC:
    return false;
}

void ec_user_devnode_close(ProcessContext *context)
{
    cdev_del(&s_fops_config.device);
    unregister_chrdev_region(s_fops_config.major, MINOR_COUNT);
}

void ec_user_comm_shutdown(ProcessContext *context)
{
    /**
     * Calling the sync flavor gives the guarantee that on the return of the
     * routine, work is not pending and not executing on any CPU.
     *
     * Its supposed to work even if the work schedules itself.
     */
    cancel_delayed_work_sync(&s_fops_config.stats_work);

    percpu_counter_destroy(&tx_ready);
}

bool ec_user_comm_enable(ProcessContext *context)
{
    s_fops_config.enabled = true;
    return true;
}

void ec_user_comm_disable(ProcessContext *context)
{
    // We need to disable the user comms
    s_fops_config.enabled = false;

    // Clear the queues now so all the memory can be freed properly before the subsystems are shutdown
    ec_user_comm_clear_queue(context);

    // Signal the polling process to wakeup
    ec_fops_comm_wake_up_reader(context);
}

void __ec_clear_tx_queue(ProcessContext *context)
{
    struct list_head *eventNode;
    struct list_head *safeNode;

    __ec_transfer_from_input_queue();

    list_for_each_safe(eventNode, safeNode, &msg_queue)
    {
        list_del_init(eventNode);
        ec_free_event(&(container_of(eventNode, CB_EVENT_NODE, listEntry)->data), context);
        percpu_counter_dec(&tx_ready);
    }
}

void ec_user_comm_clear_queue(ProcessContext *context)
{
    TRACE(DL_INFO, "%s: clear queues", __func__);

    // Clearing the queue can trigger sending an exit event which will hang when ec_send_event
    // locks this same lock. Since we're clearing the queue we don't need to send exit events.
    DISABLE_SEND_EVENTS(context);
    __ec_clear_tx_queue(context);
    ENABLE_SEND_EVENTS(context);
}

int ec_send_event(struct CB_EVENT *msg, ProcessContext *context)
{
    int                result     = -1;
    uint64_t           readyCount = 0;
    int                payload;
    CB_EVENT_NODE      *eventNode;

    TRY(ALLOW_SEND_EVENTS(context));

    TRY(s_fops_config.enabled);
    TRY(msg && ec_is_reader_connected());

    eventNode = container_of(msg, CB_EVENT_NODE, data);
    payload = __ec_precompute_payload(msg);

    // Should not happen but it can
    TRY(payload >= sizeof(struct CB_EVENT_UM));

    TRY_MSG(payload <= sizeof(struct CB_EVENT_UM_BLOB), DL_ERROR, "Payload size %d exceeds max %zu", payload, sizeof(struct CB_EVENT_UM_BLOB));

    eventNode->payload = (uint16_t)payload;

    readyCount = percpu_counter_read(&tx_ready);

    if (readyCount < g_max_queue_size)
    {
        llist_add(&(eventNode->llistEntry), &msg_queue_in);
        percpu_counter_inc(&tx_ready);
        msg = NULL;
    }

    // This should be NULL by now.
    TRY(!msg);

    // If we enqueued the event wake up the reader task if we are allowed to
    ec_fops_comm_wake_up_reader(context);

    result = 0;

CATCH_DEFAULT:
    if (msg)
    {
        // If we still have an event at this point free it now
        ++tx_dropped;
        ec_free_event(msg, context);
    }

    return result;
}

void ec_fops_comm_wake_up_reader(ProcessContext *context)
{
    // Wake up the reader task if we are allowed to. We want to avoid calling wake_up unnecessarily because it
    // uses a lock, which slows us down in send_event, which is called by all our hooks.
    if (s_fops_config.need_wakeup && ALLOW_WAKE_UP(context)) //
    {
        wake_up(&s_fops_config.wq);
        TRACE(DL_COMMS, "wakeup");
    } else
    {
        TRACE(DL_COMMS, "no wakeup");
    }
}

ssize_t ec_device_read(struct file *f,  char __user *ubuf, size_t count, loff_t *offset)
{
    ssize_t xcode = -ENOMEM;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    TRACE(DL_COMMS, "%s: start read", __func__);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // When userspace is ready to handle multiple events throw this into a loop
    xcode = __ec_copy_cbevent_to_user(ubuf, count, &context);

CATCH_DEFAULT:
    FINISH_MODULE_DISABLE_CHECK(&context);

    return xcode;
}

int ec_obtain_next_cbevent(struct CB_EVENT **cb_event, size_t count, ProcessContext *context)
{
    CB_EVENT_NODE *eventNode = NULL;
    int xcode = -ENOMEM;

    TRY_MSG(count >= sizeof(struct CB_EVENT_UM),
            DL_ERROR, "%s count too small: %zu, %zu", __func__, count, sizeof(struct CB_EVENT_UM));

    __ec_transfer_from_input_queue();

    eventNode = list_first_entry_or_null(&msg_queue, CB_EVENT_NODE, listEntry);

    TRY_SET_MSG(eventNode, -EAGAIN, DL_COMMS, "%s: empty queue", __func__);

    if (count >= eventNode->payload &&
        eventNode->payload >= sizeof(struct CB_EVENT_UM))
    {
        // when we know for sure we can send this event
        *cb_event = &eventNode->data;
        xcode = eventNode->payload;
    } else if (eventNode)
    {
        TRACE(DL_ERROR, "Invalid payload size: %d", eventNode->payload);
    }

    list_del_init(&eventNode->listEntry);
    percpu_counter_dec(&tx_ready);

CATCH_DEFAULT:
    return xcode;
}

int __ec_copy_cbevent_to_user(char __user *ubuf, size_t count, ProcessContext *context)
{
    char __user *p;
    int rc;
    uint16_t payload;
    int xcode = -EAGAIN;
    struct CB_EVENT *msg = NULL;
    struct CB_EVENT_UM __user *msg_user = (struct CB_EVENT_UM __user *)ubuf;

    // You *must* ask for at least 1 packet

    rc = ec_obtain_next_cbevent(&msg, count, context);
    if (rc < 0)
    {
        xcode = rc;
        goto CATCH_DEFAULT;
    }

    payload = (uint16_t)rc;
    p = ubuf + sizeof(struct CB_EVENT_UM);

    // Payload hdr
    rc = put_user(payload, &msg_user->payload);
    TRY_STEP(COPY_FAIL, !rc);

    // Write the main event to user
    rc = copy_to_user(&msg_user->event, msg, sizeof(*msg));
    TRY_STEP(COPY_FAIL, !rc);

    // Proc Path
    if (msg->procInfo.path && msg->procInfo.path_size)
    {
        rc = copy_to_user(p, msg->procInfo.path, msg->procInfo.path_size);
        TRY_STEP(COPY_FAIL, !rc);
        p += msg->procInfo.path_size;
    }
    // Always zero it out kaddrs
    rc = put_user(0, &msg_user->event.procInfo.path);
    TRY_STEP(COPY_FAIL, !rc);

    // Use switch for now to allow us to extend in the future
    switch (msg->eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START:
        if (msg->processStart.path && msg->processStart.path_size)
        {
            rc = copy_to_user(p, msg->processStart.path, msg->processStart.path_size);
            TRY_STEP(COPY_FAIL, !rc);
            p += msg->processStart.path_size;
        }
        rc = put_user(0, &msg_user->event.processStart.path);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
    case CB_EVENT_TYPE_FILE_CREATE:
    case CB_EVENT_TYPE_FILE_DELETE:
    case CB_EVENT_TYPE_FILE_OPEN:
    case CB_EVENT_TYPE_FILE_WRITE:
    case CB_EVENT_TYPE_FILE_CLOSE:
    case CB_EVENT_TYPE_FILE_PATH:
        if (msg->fileGeneric.path && msg->fileGeneric.path_size)
        {
            rc = copy_to_user(p, msg->fileGeneric.path, msg->fileGeneric.path_size);
            TRY_STEP(COPY_FAIL, !rc);
            p += msg->fileGeneric.path_size;
        }
        rc = put_user(0, &msg_user->event.fileGeneric.path);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    case CB_EVENT_TYPE_DNS_RESPONSE:
        if (msg->dnsResponse.records && msg->dnsResponse.record_count)
        {
            rc = copy_to_user(p, msg->dnsResponse.records,
                              msg->dnsResponse.record_count * sizeof(CB_DNS_RECORD));
            TRY_STEP(COPY_FAIL, !rc);
            p += msg->dnsResponse.record_count * sizeof(CB_DNS_RECORD);
        }
        rc = put_user(0, &msg_user->event.dnsResponse.records);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
    case CB_EVENT_TYPE_NET_CONNECT_POST:
    case CB_EVENT_TYPE_NET_ACCEPT:
    case CB_EVENT_TYPE_WEB_PROXY:
        if (msg->netConnect.actual_server && msg->netConnect.server_size)
        {
            rc = copy_to_user(p, msg->netConnect.actual_server,
                              msg->netConnect.server_size);
            TRY_STEP(COPY_FAIL, !rc);

            p += msg->netConnect.server_size;
        }
        rc = put_user(0, &msg_user->event.netConnect.actual_server);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    case CB_EVENT_TYPE_PROCESS_BLOCKED:
        if (msg->blockResponse.path && msg->blockResponse.path_size)
        {
            rc = copy_to_user(p, msg->blockResponse.path, msg->blockResponse.path_size);
            TRY_STEP(COPY_FAIL, !rc);

            p += msg->blockResponse.path_size;
        }
        rc = put_user(0, &msg_user->event.blockResponse.path);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    default:
        break;
    }

    if (p - ubuf != payload)
    {
        TRACE(DL_ERROR, "%s: Offset:%u Payload:%u", __func__,
              (unsigned int)(p - ubuf), payload);
        xcode = -ENXIO;
        goto CATCH_DEFAULT;
    }

    xcode = payload;

    ++tx_total;

    switch (msg->eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START:
    case CB_EVENT_TYPE_PROCESS_EXIT:
    case CB_EVENT_TYPE_PROCESS_LAST_EXIT:
        ++tx_process;
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
        ++tx_modload;
        break;

    case CB_EVENT_TYPE_FILE_CREATE:
    case CB_EVENT_TYPE_FILE_DELETE:
    case CB_EVENT_TYPE_FILE_WRITE:
    case CB_EVENT_TYPE_FILE_CLOSE:
    case CB_EVENT_TYPE_FILE_OPEN:
        ++tx_file;
        break;

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
    case CB_EVENT_TYPE_NET_CONNECT_POST:
    case CB_EVENT_TYPE_NET_ACCEPT:
        ++tx_net;
        break;

    case CB_EVENT_TYPE_DNS_RESPONSE:
        ++tx_dns;
        break;

    case CB_EVENT_TYPE_WEB_PROXY:
        ++tx_proxy;
        break;

    case CB_EVENT_TYPE_PROCESS_BLOCKED:
    case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
        ++tx_block;
        break;

    case CB_EVENT_TYPE_PROC_ANALYZE:
    case CB_EVENT_TYPE_HEARTBEAT:
    case CB_EVENT_TYPE_MAX:
    case CB_EVENT_TYPE_UNKNOWN:
    default:
        ++tx_other;
        break;
    }

CATCH_COPY_FAIL:
    // Check the result
    if (rc)
    {
        TRACE(DL_ERROR, "%s: copy to user failed rc=%d", __func__, rc);
        xcode = -ENXIO;
    }

    // When we start pausing tasks we will want to handle waking
    // them when we have an issue with userspace.

CATCH_DEFAULT:
    ec_free_event(msg, context);

    return xcode;
}

void __ec_transfer_from_input_queue(void)
{
    LIST_HEAD(tempList);
    struct llist_node *l_node = NULL;

    // Move the input queue into a temporary list (no lock required)
    l_node = llist_del_all(&msg_queue_in);

    CANCEL_VOID(l_node);

    // Move the contents of the input queue into a temporary list
    //  This reverses the order because the input queue is implemented as a stack
    while (l_node)
    {
        CB_EVENT_NODE *node = llist_entry(l_node, CB_EVENT_NODE, llistEntry);

        l_node = llist_next(l_node);
        list_add(&node->listEntry, &tempList);
    }

    // Splice the list onto the end of the real tx_queue
    list_splice_tail(&tempList, &msg_queue);
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
    TRACE(DL_INFO, "%s: releasing device from pid[%d]; reader_pid[%d]", __func__, ec_getpid(current), s_fops_config.reader_pid);

    if (!ec_disconnect_reader(ec_getpid(current)))
    {
        return -ECONNREFUSED;
    }

    return 0;
}

unsigned int ec_device_poll(struct file *filp, struct poll_table_struct *pts)
{
    int  xcode      = 0;
    bool msg_queued = false;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Check if messages are available. llist_empty is not guaranteed to be correct but that's ok,
    // the reader will try again.
    msg_queued = !llist_empty(&msg_queue_in) || !list_empty(&msg_queue);

    TRY_MSG(!msg_queued, DL_COMMS, "%s: msg queued so not waiting", __func__);

    // We should call poll_wait here if we want the kernel to actually
    // sleep when waiting for us. This adds us to the list of devices being waited on.
    TRACE(DL_COMMS, "%s: waiting for data", __func__);
    poll_wait(filp, &s_fops_config.wq, pts);

CATCH_DEFAULT:
    // If comms have been disabled while we were waiting send POLLHUP
    if (!s_fops_config.enabled)
    {
        xcode = POLLHUP;
    } else
    {
        // If messages are queued then poll will not wait, so no wakeup is needed when more messages are queued.
        // If messages are not queued then poll will wait, so we need to wakeup when messages are queued.
        s_fops_config.need_wakeup = !msg_queued;

        // Report if we have events to read
        xcode = msg_queued ? (POLLIN | POLLRDNORM) : 0;
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
        TRACE(DL_ERROR, "%s: Cannot process cmd=%d, process not authorized; pid[%d], reader-pid[%d]", __func__, cmd, context.pid, s_fops_config.reader_pid);
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
                mem_user                            = heartbeat.user_memory;
                mem_user_peak                       = heartbeat.user_memory_peak;
                event->heartbeat.user_memory        = heartbeat.user_memory;
                event->heartbeat.user_memory_peak   = heartbeat.user_memory_peak;
                event->heartbeat.kernel_memory      = mem_kernel;
                event->heartbeat.kernel_memory_peak = mem_kernel_peak;
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

    case CB_DRIVER_REQUEST_WEBPROXY_ENABLED:
        {
            g_webproxy_enabled = data.value;
            if (g_webproxy_enabled)
            {
                ec_netfilter_enable(&context);
            } else
            {
                ec_netfilter_disable(&context);
            }

            TRACE(DL_INFO, "Web proxy processing %s", g_webproxy_enabled ? "enabled" : "disabled");
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

    TRACE(DL_INFO, "Received action=%u", action);
    switch (action)
    {
    case CB_EVENT_ACTION_CLEAR_EVENT_QUEUE:
        ec_user_comm_clear_queue(context);
        break;

    case CB_EVENT_ACTION_ENABLE_EVENT_COLLECTOR:
        result = ec_enable_module(context) ? 0 : 1;
        break;

    case CB_EVENT_ACTION_DISABLE_EVENT_COLLECTOR:
        result = ec_disable_module(context);
        break;

    case CB_EVENT_ACTION_REQUEST_PROCESS_DISCOVERY:
        ec_process_tracking_send_process_discovery(context);
        break;

    case CB_EVENT_ACTION_REQUEST_PATH_DISCOVERY:
        ec_path_cache_send_path_discovery(context);
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
    uint32_t         curr   = s_fops_data.event_stats.curr;
    uint32_t         next   = (curr + 1) % MAX_INTERVALS;
    uint64_t         ready0 = percpu_counter_sum_positive(&tx_ready);
    int              i;
    size_t           kernel_mem;
    size_t           kernel_mem_peak;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    // I am not strictly speaking doing this operation atomicly.  This means there is a
    //  chance that a counter will be missed.  I am willing to allow that for the sake of
    //  performance.

    // tx_ready_X are live counters that rise and fall as events are generated. Add whatever
    //  is new in this variable to the current stat.

    tx_queued_t += ready0;

    // Copy over the current total to the next interval
    for (i = 0; i < NUM_STATS; ++i)
    {
        s_fops_data.event_stats.stats[next][i] = s_fops_data.event_stats.stats[curr][i];
    }
    current_stat = next;
    ++valid_stats;
    getnstimeofday(&s_fops_data.event_stats.time[next]);
    kernel_mem      = __ec_get_memory_usage(&context);
    kernel_mem_peak = mem_kernel_peak;
    mem_kernel      = kernel_mem;
    mem_kernel_peak = (kernel_mem > kernel_mem_peak ? kernel_mem : kernel_mem_peak);

    schedule_delayed_work(&s_fops_config.stats_work, s_fops_config.stats_work_delay);
}

// Print event stats
int ec_proc_show_events_avg(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = s_fops_data.event_stats.curr + MAX_INTERVALS;
    uint32_t    valid   = s_fops_data.event_stats.validStats;
    int32_t     avg1_c  = (valid >  4 ?  4 : valid);
    int32_t     avg2_c  = (valid > 20 ? 20 : valid);
    int32_t     avg3_c  = (valid > 60 ? 60 : valid);
    int32_t     avg1    = (curr - avg1_c) % MAX_INTERVALS;
    int32_t     avg2    = (curr - avg2_c) % MAX_INTERVALS;
    int32_t     avg3    = (curr - avg3_c) % MAX_INTERVALS;

    int         i;

    if (valid == 0)
    {
        seq_puts(m, "No Data\n");
        return 0;
    }

    // I only want to include valid intervals, so back the current pointer to the last valid
    curr = (curr - 1) % MAX_INTERVALS;

    seq_printf(m, " %15s | %9s | %9s | %9s | %10s |\n", "Stat", "Total",  "1 min avg", "5 min avg", "15 min avg");

    // Uncomment this to debug the averaging
    //seq_printf(m, " %15s | %9d | %9d | %9d | %10d\n", "Avgs", curr, avg1, avg2, avg3 );
    for (i = 0; i < EVENT_STATS; ++i)
    {
        // This is a circular array of elements were each element is an increasing sum from the
        //  previous element. You can always get the sum of any two elements, and divide by the
        //  number of elements between them to yield the average.
        uint64_t currentStat = s_fops_data.event_stats.stats[curr][i];

        seq_printf(m, " %15s | %9lld | %9lld | %9lld | %10lld |\n", STAT_STRINGS[i].name, currentStat,
                   (currentStat - s_fops_data.event_stats.stats[avg1][i]) / avg1_c / STAT_INTERVAL,
                   (currentStat - s_fops_data.event_stats.stats[avg2][i]) / avg2_c / STAT_INTERVAL,
                   (currentStat - s_fops_data.event_stats.stats[avg3][i]) / avg3_c / STAT_INTERVAL);
    }

    seq_puts(m, "\n");

    return 0;
}

int ec_proc_show_events_det(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = s_fops_data.event_stats.curr;
    uint32_t    valid   = min(s_fops_data.event_stats.validStats, MAX_VALID_INTERVALS);
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
            seq_printf(m, STAT_STRINGS[j].num_format, s_fops_data.event_stats.stats[right][j] - s_fops_data.event_stats.stats[left][j]);
        }
        seq_puts(m, "\n");
    }

    return 0;
}

ssize_t ec_proc_show_events_rst(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    int i;

    // Cancel the currently scheduled job
    cancel_delayed_work(&s_fops_config.stats_work);

    // I do not need to zero out everything, just the new active interval
    current_stat = 0;
    valid_stats  = 0;
    for (i = 0; i < NUM_STATS; ++i)
    {
        // We make sure the first and last interval are 0 for the average calculations
        s_fops_data.event_stats.stats[0][i]                 = 0;
        s_fops_data.event_stats.stats[MAX_INTERVALS - 1][i] = 0;
    }
    getnstimeofday(&s_fops_data.event_stats.time[0]);

    // Resatrt the job from now
    schedule_delayed_work(&s_fops_config.stats_work, s_fops_config.stats_work_delay);
    return size;
}

int ec_proc_current_memory_avg(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = s_fops_data.event_stats.curr;

    int         i;

    for (i = MEM_START; i < MEM_STATS; ++i)
    {
        // This is a circular array of elements were each element is an increasing sum from the
        //  previous element. You can always get the sum of any two elements, and divide by the
        //  number of elements between them to yield the average.
        uint64_t currentStat = s_fops_data.event_stats.stats[curr][i];

        seq_printf(m, "%9lld ", currentStat);
    }

    seq_puts(m, "\n");

    return 0;
}

int ec_proc_current_memory_det(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = s_fops_data.event_stats.curr;
    uint32_t    valid   = min(s_fops_data.event_stats.validStats, MAX_VALID_INTERVALS);
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
            seq_printf(m, STAT_STRINGS[j].num_format, s_fops_data.event_stats.stats[right][j]);
        }
        //seq_printf(m, " %9lld | %9lld |", left, right );
        seq_puts(m, "\n");
    }

    return 0;
}

size_t __ec_get_memory_usage(ProcessContext *context)
{
    return ec_mem_cache_get_memory_usage(context) +
           ec_mem_allocated_size(context) +
           ec_hashtbl_get_memory(context);
}

// Eventually do this just before attempting to enqueue the event.
int __ec_precompute_payload(struct CB_EVENT *cb_event)
{
    int payload = 0;

    if (!cb_event)
    {
        return -EINVAL;
    }

    payload += sizeof(struct CB_EVENT_UM);

    if (cb_event->procInfo.path && cb_event->procInfo.path_size)
    {
        if (cb_event->procInfo.path_size > PATH_MAX)
        {
            TRACE(DL_WARNING, "procInfo.path_size: %d, %s", cb_event->procInfo.path_size, cb_event->procInfo.path);
        }

        cb_event->procInfo.path_offset = payload;
        payload += cb_event->procInfo.path_size;
    }

    switch (cb_event->eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START:
        if (cb_event->processStart.path && cb_event->processStart.path_size)
        {
            if (cb_event->processStart.path_size > PATH_MAX)
            {
                TRACE(DL_WARNING, "processStart.path_size: %d, %s", cb_event->processStart.path_size,
                      cb_event->processStart.path);
            }

            cb_event->processStart.path_offset = payload;
            payload += cb_event->processStart.path_size;
        }
        break;

    case CB_EVENT_TYPE_PROCESS_EXIT:
    case CB_EVENT_TYPE_PROCESS_LAST_EXIT:
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
    case CB_EVENT_TYPE_FILE_CREATE:
    case CB_EVENT_TYPE_FILE_DELETE:
    case CB_EVENT_TYPE_FILE_OPEN:
    case CB_EVENT_TYPE_FILE_WRITE:
    case CB_EVENT_TYPE_FILE_CLOSE:
    case CB_EVENT_TYPE_FILE_PATH:
        if (cb_event->fileGeneric.path && cb_event->fileGeneric.path_size)
        {
            if (cb_event->fileGeneric.path_size > PATH_MAX)
            {
                TRACE(DL_WARNING, "fileGeneric.path_size: %d, %s", cb_event->fileGeneric.path_size,
                      cb_event->fileGeneric.path);
            }

            cb_event->fileGeneric.path_offset = payload;
            payload += cb_event->fileGeneric.path_size;
        }
        break;

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
    case CB_EVENT_TYPE_NET_CONNECT_POST:
    case CB_EVENT_TYPE_NET_ACCEPT:
    case CB_EVENT_TYPE_WEB_PROXY:
        if (cb_event->netConnect.actual_server && cb_event->netConnect.server_size)
        {
            if (cb_event->netConnect.server_size > PATH_MAX)
            {
                TRACE(DL_WARNING, "netConnect.server_size: %d, %s", cb_event->netConnect.server_size,
                      cb_event->netConnect.actual_server);
            }

            cb_event->netConnect.server_offset = payload;
            payload += cb_event->netConnect.server_size;
        }
        break;

    case CB_EVENT_TYPE_DNS_RESPONSE:
        if (cb_event->dnsResponse.records && cb_event->dnsResponse.record_count)
        {
            if (cb_event->dnsResponse.record_count * sizeof(CB_DNS_RECORD) > PATH_MAX)
            {
                TRACE(DL_WARNING, "dnsResponse.record_count: %d, %zu", cb_event->dnsResponse.record_count,
                      cb_event->dnsResponse.record_count * sizeof(CB_DNS_RECORD));
            }

            cb_event->dnsResponse.record_offset = payload;
            payload += cb_event->dnsResponse.record_count * sizeof(CB_DNS_RECORD);
        }

        break;

    case CB_EVENT_TYPE_PROCESS_BLOCKED:
        if (cb_event->blockResponse.path && cb_event->blockResponse.path_size)
        {
            if (cb_event->blockResponse.path_size > PATH_MAX)
            {
                TRACE(DL_WARNING, "blockResponse.path_size: %d, %s", cb_event->blockResponse.path_size,
                      cb_event->blockResponse.path);
            }

            cb_event->blockResponse.path_offset = payload;
            payload += cb_event->blockResponse.path_size;
        }
        break;

    case CB_EVENT_TYPE_HEARTBEAT:
        break;

    // Internal To The Kernel
    case CB_EVENT_TYPE_PROCESS_START_FORK:
    case CB_EVENT_TYPE_PROCESS_START_EXEC:
        return -EINVAL;

    // Unused
    case CB_EVENT_TYPE_UNKNOWN:
    case CB_EVENT_TYPE_PROC_ANALYZE:
    case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
        break;

    default:
        if (cb_event->eventType < CB_EVENT_TYPE_UNKNOWN || cb_event->eventType >= CB_EVENT_TYPE_MAX)
        {
            return -EINVAL;
        }
        break;
    }

    return payload;
}
