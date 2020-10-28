// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "findsyms.h"
#include "process-tracking.h"
#include "network-tracking.h"
#include "file-process-tracking.h"
#include "cb-isolation.h"
#include "mem-cache.h"
#include "path-buffers.h"
#include "cb-spinlock.h"
#include "cb-banning.h"
#include "hook-tracking.h"
#include "tests/run-tests.h"

#ifdef HOOK_SELECTOR
#define HOOK_MASK  0x0000000000000000
#else
#define HOOK_MASK  0xFFFFFFFFFFFFFFFF
#endif

uint32_t g_traceLevel = (uint32_t)(DL_INIT | DL_SHUTDOWN | DL_WARNING | DL_ERROR);
uint64_t g_enableHooks = HOOK_MASK;
uid_t    g_cb_server_uid = (uid_t)-1;
int64_t  g_cb_ignored_pid_count;
pid_t    g_cb_ignored_pids[CB_SENSOR_MAX_PIDS];
int64_t  g_cb_ignored_uid_count;
uid_t    g_cb_ignored_uids[CB_SENSOR_MAX_UIDS];
bool     g_exiting;
uint32_t g_max_queue_size_pri0 = DEFAULT_P0_QUEUE_SIZE;
uint32_t g_max_queue_size_pri1 = DEFAULT_P1_QUEUE_SIZE;
uint32_t g_max_queue_size_pri2 = DEFAULT_P2_QUEUE_SIZE;
bool     g_run_self_tests;

CB_DRIVER_CONFIG g_driver_config = {
    ALL_FORKS_AND_EXITS,
    ENABLE,
    ENABLE,
    ENABLE,
    ENABLE
};
// checkpatch-ignore: SYMBOLIC_PERMS
module_param(g_traceLevel, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(g_max_queue_size_pri0, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(g_max_queue_size_pri1, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(g_max_queue_size_pri2, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(g_run_self_tests, bool, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

#ifdef HOOK_SELECTOR
module_param(g_enableHooks, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
#endif
// checkpatch-no-ignore: SYMBOLIC_PERMS
//MODULE_PARAM_DESC(g_traceLevel, "Debug trace level");

INIT_CB_RESOLVED_SYMS();
atomic64_t       module_used      = ATOMIC64_INIT(0);

ModuleStateInfo  g_module_state_info = { 0 };

static bool module_state_info_initialize(ProcessContext *context);

static void module_state_info_shutdown(ProcessContext *context);

static int _cb_sensor_enable_module_initialize_memory(ProcessContext *context);

static void _cb_sensor_disable_module_shutdown(ProcessContext *context);

static void set_module_state(ProcessContext *context, ModuleState newState);

static bool disable_peer_modules(ProcessContext *context);

static bool cb_proc_initialize(ProcessContext *context);

static void cb_proc_shutdown(ProcessContext *context);

struct proc_dir_entry *g_cb_proc_dir;

bool disable_if_not_connected(ProcessContext *context, char *src_module_name, char **failure_reason)
{
    TRACE(DL_INIT, "In %s received call to disable from module %s", __func__, src_module_name);

    if (is_reader_connected())
    {
        *failure_reason = "Cannot disable " CB_APP_MODULE_NAME " is connected to reader.";
        return false;
    }

    {
        int ret = cbsensor_disable_module(context);

        if (ret < 0)
        {
            TRACE(DL_ERROR, "Disabled failed with error %d", ret);
            *failure_reason = "Disable operation failed with unexpected error";
            return false;
        }
    }

    return true;
}

int cb_proc_state(struct seq_file *m, void *v)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    char *state_str = NULL;
    ModuleState state = get_module_state(&context);

    switch (state)
    {
        case ModuleStateDisabling:
            state_str = "disabling";
            break;
        case ModuleStateEnabling:
            state_str = "enabling";
            break;
        case ModuleStateEnabled:
            state_str = "enabled";
            break;
        case ModuleStateDisabled:
            state_str = "disabled";
            break;
    }

    seq_printf(m, "%s\n", state_str);

    return 0;
}

static int cb_proc_state_open(struct inode *inode, struct file *file)
{
    return single_open(file, cb_proc_state, PDE_DATA(inode));
}

static const struct file_operations cb_fops = {
        .owner      = THIS_MODULE,
        .open       = cb_proc_state_open,
        .read       = seq_read,
        .write      = NULL,
        .release    = single_release,
};

const char *PROC_STATE_FILENAME = CB_APP_MODULE_NAME "_state";

static int __init cbsensor_init(void)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));
    // Here we look up symbols at runtime to fill in the CB_RESOLVED_SYMS struct.
#undef CB_RESOLV_VARIABLE
#undef CB_RESOLV_FUNCTION
#undef CB_RESOLV_FUNCTION_310
#define CB_RESOLV_VARIABLE(V_TYPE, V_NAME) { #V_NAME, strlen(#V_NAME), (unsigned long *)&g_resolvedSymbols.V_NAME },
#define CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL) CB_RESOLV_VARIABLE(F_TYPE, F_NAME)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    #define CB_RESOLV_FUNCTION_310(F_TYPE, F_NAME, ARGS_DECL) CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL)
#else
    #define CB_RESOLV_FUNCTION_310(F_TYPE, F_NAME, ARGS_DECL)
#endif

    struct symbols_s symbols[] = {
            CB_RESOLV_SYMBOLS
            { {0}, 0, 0 }
    };

    TRACE(DL_INIT, "%s version %s (%s)",
           CB_APP_MODULE_NAME, CB_APP_VERSION_STRING, CB_APP_BUILD_DATE);
    //
    // Initialize Subsystems
    //
    memset(&g_cb_ignored_pids[0], 0, sizeof(pid_t)*CB_SENSOR_MAX_PIDS);
    memset(&g_cb_ignored_uids[0], 0xFF, sizeof(uid_t)*CB_SENSOR_MAX_PIDS);

    // Actually do the lookup
    cb_findsyms_init(&context, symbols);

    cb_mem_cache_init(&context);
    hashtbl_generic_init(&context);
    reader_init();

    TRY_STEP(DEFAULT,    module_state_info_initialize(&context));
    TRY_STEP(STATE_INFO, netfilter_initialize(&context, g_enableHooks));
    TRY_STEP(NET_FIL,    lsm_initialize(&context, g_enableHooks));
    TRY_STEP(LSM,        syscall_initialize(&context, g_enableHooks));
    TRY_STEP(SYSCALL,    user_devnode_init(&context));
    TRY_STEP(USER_DEV_NODE,  hook_tracking_initialize(&context));

    if (g_run_self_tests)
    {
        bool passed = false;

        DISABLE_SEND_EVENTS(&context);
        DISABLE_WAKE_UP(&context);

        // We need everything initialized for running the self-tests but we don't
        // want the hooks enabled so we do a separate init/shutdown just for the
        // tests. The shutdown here will warn if we fail to free anything.
        // Everything will be re-inited by cbsensor_enable_module().
        _cb_sensor_enable_module_initialize_memory(&context);
        passed = run_tests(&context);
        _cb_sensor_disable_module_shutdown(&context);

        ENABLE_SEND_EVENTS(&context);
        ENABLE_WAKE_UP(&context);

        TRY_STEP(USER_DEV_NODE, passed);
    }

    /**
     * Setup the module to come up as enabled when its loaded. Enabling the module, means it will
     * start tracking processes. This should handle the following cases:
     *
     * - On a reboot, the module will be loaded before the agent starts up, but will have a
     * more accurate state of the processes.
     *
     * - On a upgrade/reinstall the shutdown of the event-collector will disable the old module,
     * and the startup of the new event-collector will insmod the new module.
     * This new module will automatically come up as enabled.
     *
     */

    TRY_STEP(USER_DEV_NODE, !cbsensor_enable_module(&context));

    TRACE(DL_INIT, "Kernel sensor initialization complete");
    return 0;

CATCH_USER_DEV_NODE:
    user_devnode_close(&context);
CATCH_SYSCALL:
    syscall_shutdown(&context, g_enableHooks);
CATCH_LSM:
    lsm_shutdown(&context);
CATCH_NET_FIL:
    netfilter_cleanup(&context, g_enableHooks);
CATCH_STATE_INFO:
    module_state_info_shutdown(&context);
CATCH_DEFAULT:
    return -1;
}


void cbsensor_shutdown(ProcessContext *context)
{
    // If the hooks have been modified abort the shutdown.
    CANCEL_VOID_MSG(!(syscall_hooks_changed(context, g_enableHooks) || lsm_hooks_changed(context, g_enableHooks)),
                    DL_WARNING, "Hooks have changed, unable to shutdown");

    /**
     *
     * Disables the module & free up the memory resources.
     * Refer to function header for cbsensor_disable_module, to get more details.
     */
    CANCEL_VOID((cbsensor_disable_module(context) == 0));

    // Remove hooks
    syscall_shutdown(context, g_enableHooks);
    lsm_shutdown(context);
    netfilter_cleanup(context, g_enableHooks);
}

static void __exit cbsensor_cleanup(void)
{
    uint64_t l_module_used;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    TRACE(DL_SHUTDOWN, "Cleaning up module...");

    // I want to globally notify that we are exiting, but not until the hooks have been removed
    g_exiting = true;

    // We have to be sure we're not in a hook. Wait here until nothing is using our module.
    // NOTE: We only care about the actual hooks.  If our dev node is open, Linux will already
    //  prevent unloading.
    while ((l_module_used = atomic64_read(&module_used)) != 0)
    {
        TRACE(DL_SHUTDOWN, "Module has %lld active hooks, delaying shutdown...", l_module_used);
        ssleep(5);
    }

    hook_tracking_shutdown(&context);
    module_state_info_shutdown(&context);
    hashtbl_generic_destoy(&context);
    cb_mem_cache_shutdown(&context);

    tracepoint_synchronize_unregister();

    TRACE(DL_SHUTDOWN, "%s driver cleanup complete.", CB_APP_MODULE_NAME);
}


/**
 * Disables the module.
 *
 * This call will wait for actively running hooks to finish. (To be precise after this call,
 * the hooks may execute, but when they execute they will act as a no-op, so will never run code
 * that accesses any of the global resources like process-tracking, connection tracking tables)
 * The call will also free the memory resources (like the tracking tables.)
 *
 * The call does not remove the hooks, this code is used when
 * - (a) When the user explicitly issues a control command  to  disables the module, or when
 * - (b) In the shutdown sequence, before unhooking the lsm and the system calls.
 *
 * Implementation details:
 *  - The interlock between this call and individual hooks, gurantees that this call should always
 *   finish even on a busy system (busy meaning there are more than one hooks running almost all the
 *   time.). Here is how
 *    - This call does its work in 3 steps,
 *      Step 1: moves the state from enabled to disabling
 *      (under a state-lock.). After this point, if the kernel were to enter a hook, it will
 *      see the state change and not increment the active_call_count, instead just pass-through,
 *      and exit the hook. (this test and set is again done under a state_lock.). Thus even on a busy
 *      system we should always be able to disable
 *      Step 2: Waits for the active_call_count to reach 0, note the inter-lock in step 1, should
 *      gurantee that the active_call_count should only reduce in this step.
 *      Step 3: Move the state to disabled.
 *
 *  - We did play around with the idea to using the generic wait_for_completion machinery in linux.
 *    It does work for the problem below, but decided on dropping on it, the MR
 *    "https://gitlab.bit9.local/cbsensor/endpoint-common/merge_requests/784" talks through the
 *    reasons for dropping this.
 *
 */
int cbsensor_disable_module(ProcessContext *context)
{
    int print_count         = 0;

    cb_write_lock(&g_module_state_info.module_state_lock, context);

    switch (g_module_state_info.module_state)
    {
        case ModuleStateDisabled:
            TRACE(DL_INFO, "%s Received a request to disable a module that's already disabled, so no-op. ", __func__);
            cb_write_unlock(&g_module_state_info.module_state_lock, context);
            return 0;

        case ModuleStateDisabling:
            TRACE(DL_ERROR,  "%s Received an UNEXPECTED call to disable module while module is in disabling state", __func__);
            cb_write_unlock(&g_module_state_info.module_state_lock, context);
            return -EPERM;

        case ModuleStateEnabling:
            TRACE(DL_ERROR,  "%s Received an UNEXPECTED call to disable module while module is in enabling state", __func__);
            cb_write_unlock(&g_module_state_info.module_state_lock, context);
            return -EPERM;

        case ModuleStateEnabled:
            TRACE(DL_INIT,  "%s Received a request to disable module", __func__);
            g_module_state_info.module_state = ModuleStateDisabling;
            break;
    }

    cb_write_unlock(&g_module_state_info.module_state_lock, context);

    while (true)
    {
        uint64_t l_active_call_count = 0;

        l_active_call_count = atomic64_read(&g_module_state_info.module_active_call_count);
        if (l_active_call_count != 0)
        {
            // Reduce how often we print a message about active hooks
            if ((++print_count % 5) == 0)
            {
                TRACE(DL_INIT,  "%s Module has %lld active hooks, delaying disable...",  __func__, l_active_call_count);
                hook_tracking_print_active(context);
            }
            ssleep(1);
            continue;
        }

        break;
    }

    TRACE(DL_INIT,  "%s Module active call count is now zero, so safe free memory resources, held by tracking tables.", __func__);

    DISABLE_WAKE_UP(context);

    _cb_sensor_disable_module_shutdown(context);

    set_module_state(context, ModuleStateDisabled);

    TRACE(DL_INIT,  "%s: Module successfully disabled.", __func__);

    ENABLE_WAKE_UP(context);

    return 0;
}


/**
 * Using the lock here, just to get a consistent read for the module_state enum.
 */
ModuleState get_module_state(ProcessContext *context)
{
    ModuleState _state;

    cb_write_lock(&g_module_state_info.module_state_lock, context);
    _state = g_module_state_info.module_state;
    cb_write_unlock(&g_module_state_info.module_state_lock, context);

    return _state;
}

static void set_module_state(ProcessContext *context, ModuleState newState)
{
    cb_write_lock(&g_module_state_info.module_state_lock, context);
    g_module_state_info.module_state = newState;
    cb_write_unlock(&g_module_state_info.module_state_lock, context);
}

/**
 *
 * The call will enable the module when disabled.
 * It does the converse of what disable does, its much simpler though.
 *
 * When disabled, the call will first transition the state to enabling (under the state-lock) and
 * then move it to enabled.
 * Transition to enabling
 *  - Allows for mutual exclusion, that this thread now owns the responsibility to move
 * the state to enabled, as in if this call were to be run in another thread while the 1st call
 * is enabling the 2nd call will return error.
 * - Lets this thread release the state-lock, this is very important (I ended up chasing my tail
 *  trying to figure this out.). The calls that initialize memory do call kmem_cache_create, deep
 *  in kmem_cache_create's call-stack it attempts to send some notification over a UDS socket,
 *  which then ends up calling the hook "on_sock_rcv_skb". This call will also attempt to do
 *  the state check so will try to grab the same lock. Thus the need to release the lock before
 *  making the calls to initialize memory.
 *
 */
int cbsensor_enable_module(ProcessContext *context)
{
    cb_write_lock(&g_module_state_info.module_state_lock, context);

    switch (g_module_state_info.module_state)
    {
        case ModuleStateDisabling:
            TRACE(DL_ERROR,  "%s Received an UNEXPECTED call to enable module while module is in disabling state", __func__);
            cb_write_unlock(&g_module_state_info.module_state_lock, context);
            return -EPERM;

        case ModuleStateEnabling:
            TRACE(DL_ERROR,  "%s Received an UNEXPECTED call to enable module while module is in enabling state", __func__);
            cb_write_unlock(&g_module_state_info.module_state_lock, context);
            return -EPERM;
        case ModuleStateEnabled:
        {
            TRACE(DL_INFO, "%s Received a request to enable a module that's already enabled, so no-op. ", __func__);
            cb_write_unlock(&g_module_state_info.module_state_lock, context);
            return 0;
        }
        case ModuleStateDisabled:
        {
            g_module_state_info.module_state = ModuleStateEnabling;
            cb_write_unlock(&g_module_state_info.module_state_lock, context);

            {
                DECLARE_ATOMIC_CONTEXT(atomic_context, getpid(current));

                int result = _cb_sensor_enable_module_initialize_memory(context);

                if (result != 0)
                {
                    TRACE(DL_ERROR,
                          "Call _cb_sensor_enable_module_initialize_memory failed with error %d",
                          result);

                    set_module_state(context, ModuleStateDisabled);
                    return result;
                }

                enumerate_and_track_all_tasks(&atomic_context);
            }

            set_module_state(context, ModuleStateEnabled);
            TRACE(DL_INIT, "%s Module enable operation succeeded. ", __func__);
        }
            break;
    }

    return 0;
}


static int _cb_sensor_enable_module_initialize_memory(ProcessContext *context)
{
    TRY_STEP(DEFAULT,   disable_peer_modules(context));
    TRY_STEP(DEFAULT,   path_buffers_init(context));
    TRY_STEP(BUFFERS,   cb_proc_initialize(context));
    TRY_STEP(PROC_DIR,  user_comm_initialize(context));
    TRY_STEP(USER_COMM, logger_initialize(context));
    TRY_STEP(LOGGER,    process_tracking_initialize(context));
    TRY_STEP(PROC,      network_tracking_initialize(context));
    TRY_STEP(NET_TR,    cbBanningInitialize(context));
    TRY_STEP(BAN,       !CbInitializeNetworkIsolation(context));
    TRY_STEP(NET_IS,    file_helper_init(context));
    TRY_STEP(NET_IS,    task_initialize(context));
    TRY_STEP(TASK,      file_process_tracking_init(context));
    TRY_STEP(FILE_PROC, cb_stats_proc_initialize(context));

    return 0;

CATCH_FILE_PROC:
    file_process_tracking_shutdown(context);
CATCH_TASK:
    task_shutdown(context);
CATCH_NET_IS:
    CbDestroyNetworkIsolation(context);
CATCH_BAN:
    cbBanningShutdown(context);
CATCH_NET_TR:
    network_tracking_shutdown(context);
CATCH_PROC:
    process_tracking_shutdown(context);
CATCH_LOGGER:
    logger_shutdown(context);
CATCH_USER_COMM:
    user_comm_shutdown(context);
CATCH_PROC_DIR:
    cb_proc_shutdown(context);
CATCH_BUFFERS:
    path_buffers_shutdown(context);
CATCH_DEFAULT:
    return -ENOMEM;
}

static void _cb_sensor_disable_module_shutdown(ProcessContext *context)
{
    /**
     * Shutdown the different subsystems, note order is important here.
     * Need to shutdown subsystems in the reverse order of dependency.
     */
    cb_stats_proc_shutdown(context);
    task_shutdown(context);
    CbDestroyNetworkIsolation(context);
    cbBanningShutdown(context);
    user_comm_shutdown(context);
    network_tracking_shutdown(context);
    process_tracking_shutdown(context);
    logger_shutdown(context);
    file_process_tracking_shutdown(context);
    path_buffers_shutdown(context);
    cb_proc_shutdown(context);
}

static bool disable_peer_modules(ProcessContext *context)
{
    struct list_head peer_modules = LIST_HEAD_INIT(peer_modules);
    struct PEER_MODULE *elem = NULL;
    bool result = false;

    result = lookup_peer_module_symbols(context, &peer_modules);
    if (!result)
    {
        goto Exit;
    }

    list_for_each_entry(elem, &peer_modules, list)
    {
        char *err_str = NULL;

        if (!elem->disable_fn)
        {
            TRACE(DL_INIT, "Skipping disable for module %s, no disable function found", elem->module_name);
            continue;
        }

        result = elem->disable_fn(CB_APP_MODULE_NAME, &err_str);
        if (!result)
        {
            TRACE(DL_ERROR, "Request to disable module %s, failed with error: %s",
                  elem->module_name,
                  err_str?err_str:"unknown");
            goto Exit;
        }
    }

Exit:
    free_peer_module_symbols(&peer_modules);

    return result;
}

static bool module_state_info_initialize(ProcessContext *context)
{
    cb_spinlock_init(&g_module_state_info.module_state_lock, context);

    g_module_state_info.module_state = ModuleStateDisabled;

    proc_create(PROC_STATE_FILENAME, 0400, NULL, &cb_fops);

    return true;
}

static void module_state_info_shutdown(ProcessContext *context)
{
    remove_proc_entry(PROC_STATE_FILENAME, NULL);
    cb_spinlock_destroy(&g_module_state_info.module_state_lock, context);
}

static bool cb_proc_initialize(ProcessContext *context)
{
    g_cb_proc_dir = proc_mkdir(CB_APP_PROC_DIR, NULL);
    TRY(g_cb_proc_dir);

    return true;

CATCH_DEFAULT:
    return false;
}

static void cb_proc_shutdown(ProcessContext *context)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    proc_remove(g_cb_proc_dir);
#else
    remove_proc_entry(CB_APP_PROC_DIR, NULL);
#endif
}


module_init(cbsensor_init);
module_exit(cbsensor_cleanup);

MODULE_LICENSE("GPL");
