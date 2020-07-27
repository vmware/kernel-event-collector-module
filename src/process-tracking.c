// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/binfmts.h>
#include <linux/cred.h>
#endif
#include "process-tracking-private.h"
#include "file-process-tracking.h"
#include "event-factory.h"
#include "path-buffers.h"
#include "cb-spinlock.h"

static void hashtbl_delete_callback(void *procp, ProcessContext *context);
static void shareddata_print_callback(void *data, ProcessContext *context);

static SharedTrackingData *process_tracking_alloc_shared_data(ProcessContext *context);
static void process_tracking_init_shared_data(SharedTrackingData *shared_data, ProcessContext *context);
static ProcessTracking *process_tracking_add_process(ProcessTracking *procp, ProcessContext *context);

process_tracking_data g_process_tracking_data = { 0, };

// TODO set this list dynamically via ioctl
// For now, the interpreter list is set from this static array.
char  *static_interpreter_names[] = {
    "bash", "sh", "csh", "zsh", "ksh", "perl", "python", "ruby", "java", "js", "node", "firefox", "chrome", "lua",
    "php", "tcl", "dash", "pwsh"};
char **g_interpreter_names = static_interpreter_names;
int    g_interpreter_names_count = sizeof(static_interpreter_names)/sizeof(char *);

bool g_print_proc_on_delete;

#define CB_PT_CACHE_OBJ_SZ  256

bool process_tracking_should_track_user(void)
{
    return g_driver_config.report_process_user == ENABLE;
}

bool process_tracking_initialize(ProcessContext *context)
{
    g_print_proc_on_delete = false;
    g_process_tracking_data.table = hashtbl_init_generic(
                                                    context,
                                                    8192,
                                                    sizeof(ProcessTracking),
                                                    CB_PT_CACHE_OBJ_SZ,
                                                    "pt_cache",
                                                    sizeof(PT_TBL_KEY),
                                                    offsetof(ProcessTracking, pt_key),
                                                    offsetof(ProcessTracking, pt_link),
                                                    offsetof(ProcessTracking, reference_count),
                                                    hashtbl_delete_callback);
    TRY(g_process_tracking_data.table);

    TRY(cb_mem_cache_create(&g_process_tracking_data.shared_data_cache, "pt_shared_data_cache", sizeof(SharedTrackingData), context));

    return true;

CATCH_DEFAULT:
    process_tracking_shutdown(context);
    return false;
}

void process_tracking_shutdown(ProcessContext *context)
{
    g_print_proc_on_delete = true;

    if (g_process_tracking_data.table)
    {
        hashtbl_shutdown_generic(g_process_tracking_data.table, context);
        g_process_tracking_data.table = NULL;
    }

    cb_mem_cache_destroy(&g_process_tracking_data.shared_data_cache, context, shareddata_print_callback);

    g_print_proc_on_delete = false;
}

ProcessTracking *process_tracking_get_process(pid_t pid, ProcessContext *context)
{
    PT_TBL_KEY key = { pid };

    ProcessTracking *procp = ((ProcessTracking *)hashtbl_get_generic(g_process_tracking_data.table, &key, context));

    return procp;
}

// Check whether path points at an interpreter.
bool process_tracking_is_interpreter(const char *path)
{
    if (path)
    {
        const char *proc_name = process_tracking_get_proc_name(path);
        int i;

        for (i = 0; i < g_interpreter_names_count; i++)
        {
            char *found = strstr(proc_name, g_interpreter_names[i]);
            // Does process filename start with the interpreter name? This includes e.g. python3/perl5 but
            // does not include every filename containing 'sh' anywhere, e.g. ssh
            if (found && found == proc_name)
            {
                return true;
            }
        }
    }

    return false;
}

ProcessTracking *process_tracking_create_process(
        pid_t               pid,
        pid_t               parent,
        pid_t               tid,
        uid_t               uid,
        uid_t               euid,
        time_t              start_time,
        int                 action,
        struct task_struct *taskp,
        bool                is_real_start,
        ProcessContext *context)
{
    ProcessTracking    *procp        = NULL;
    SharedTrackingData *shared_data  = NULL;
    ProcessTracking    *parent_procp = NULL;
    char               *msg          = (is_real_start ? "" : "<FAKE> ");
    ProcessDetails      posix_parent_details      = { 0 };
    ProcessDetails      posix_grandparent_details = { 0 };

    // If this start is a fork we need to pull the shared struct from the parent
    if (action == CB_PROCESS_START_BY_FORK)
    {
        parent_procp = process_tracking_get_process(parent, context);
        if (parent_procp)
        {
            // Increase the reference count on the shared data (for local function)
            shared_data = process_tracking_get_shared_data_ref(parent_procp->shared_data, context);
            posix_parent_details      = parent_procp->posix_details;
            posix_grandparent_details = parent_procp->posix_parent_details;

            process_tracking_put_process(parent_procp, context);
        }
    }

    // We don't have a shared_data object from our parent, so create one now.  This
    //  will happen in three cases.
    //  1. We observed some event on this process
    //  2. We saw a fork, but the parent is not tracked
    //  3. We saw an exec on this process
    if (!shared_data)
    {
        struct task_struct *parent_task  = (taskp       ? taskp->real_parent : NULL);
        struct task_struct *gparent_task = (parent_task ? parent_task->real_parent : NULL);

        // TODO: We really need to build my parent
        // This gives us a local reference
        shared_data = process_tracking_alloc_shared_data(context);
        if (!shared_data)
        {
            return NULL;
        }

        shared_data->exec_details.pid                = parent;
        shared_data->exec_details.start_time         = start_time;
        get_devinfo_from_task(taskp, &shared_data->exec_details.device, &shared_data->exec_details.inode);

        shared_data->exec_parent_details.pid         = (gparent_task ? getpid(gparent_task) : 1);
        shared_data->exec_parent_details.start_time  = get_null_time();
        get_devinfo_from_task(parent_task, &shared_data->exec_details.device, &shared_data->exec_details.inode);

        shared_data->exec_grandparent_details.pid         = 0;
        shared_data->exec_grandparent_details.device      = 0;
        shared_data->exec_grandparent_details.inode       = 0;
        shared_data->exec_grandparent_details.start_time  = get_null_time();

        shared_data->path_found   = false;
        shared_data->exec_count   = 1;

        posix_parent_details      = shared_data->exec_details;
        posix_grandparent_details = shared_data->exec_parent_details;

        shared_data->is_interpreter = process_tracking_is_interpreter(shared_data->path);
    }

    procp = (ProcessTracking *)hashtbl_alloc_generic(g_process_tracking_data.table, context);
    if (procp)
    {
        procp->pt_key.pid                 = pid;
        procp->tid                        = tid;
        procp->uid                        = uid;
        procp->euid                       = euid;
        procp->action                     = action;
        procp->process_op_cnt             =
            procp->process_create         =
            procp->process_create_by_fork =
            procp->process_create_by_exec =
            procp->childproc_cnt          =
            procp->file_op_cnt            =
            procp->file_map_exec          =
            procp->file_create            =
            procp->file_delete            =
            procp->file_open              =
            procp->file_write             =
            procp->file_close             =
            procp->net_op_cnt             =
            procp->net_connect            =
            procp->net_accept             =
            procp->net_dns                = 0;
        procp->is_real_start              = is_real_start;
        procp->shared_data                = NULL;
        procp->parent_shared_data         = NULL;
        procp->exec_blocked               = false;

        procp->posix_details.pid         = pid;
        procp->posix_details.device      = shared_data->exec_details.device;
        procp->posix_details.inode       = shared_data->exec_details.inode;
        procp->posix_details.start_time  = start_time;

        procp->posix_parent_details      = posix_parent_details;
        procp->posix_grandparent_details = posix_grandparent_details;
        atomic64_set(&procp->reference_count, 1);

        g_process_tracking_data.op_cnt += 1;
        g_process_tracking_data.create += 1;

        if (action == CB_PROCESS_START_BY_FORK)
        {
            g_process_tracking_data.create_by_fork += 1;
        } else if (action == CB_PROCESS_START_BY_EXEC)
        {
            g_process_tracking_data.create_by_exec += 1;
        }

        process_tracking_set_shared_data(procp, shared_data, context);

        procp = process_tracking_add_process(procp, context);
        TRY(procp);


        // We have recorded this in the tracking table, so mark it as active
        atomic64_inc(&shared_data->active_process_count);

        TRACE(DL_PROC_TRACKING, "TRACK-INS %s%s of %d by %d (reported as %d by %d) (active: %ld)",
              msg,
              process_tracking_get_path(shared_data),
              pid,
              parent,
              shared_data->exec_details.pid,
              shared_data->exec_parent_details.pid,
              atomic64_read(&shared_data->active_process_count));
    }

CATCH_DEFAULT:
    // Always drop the ref held by this local function
    process_tracking_release_shared_data_ref(shared_data, context);

    return procp;
}

ProcessTracking *process_tracking_update_process(
    pid_t               pid,
    pid_t               tid,
    uid_t               uid,
    uid_t               euid,
    uint64_t            device,
    uint64_t            inode,
    char *path,
    bool                path_found,
    time_t              start_time,
    int                 action,
    struct task_struct *taskp,
    CB_EVENT_TYPE       event_type,
    bool                is_real_start,
    ProcessContext     *context)
{
    ProcessTracking    *procp              = NULL;
    SharedTrackingData *shared_data        = NULL;
    SharedTrackingData *parent_shared_data = NULL;
    pid_t               parent             = getppid(taskp);
    struct task_struct *parent_task        = (taskp       ? taskp->real_parent : NULL);
    char               *msg                = "";
    bool isExecOther = false;
    bool was_last_active_process = false;

    procp = process_tracking_get_process(pid, context);
    if (!procp)
    {
        msg = "<FAKE> ";

        if (!is_process_tracked(parent, context))
        {
            if (is_task_valid(parent_task) && parent_task->mm)
            {
                // if the task has not exited and it is a userspace task then it should
                // be tracked
                TRACE(DL_WARNING, "taking fake event path for non-kernel task %d", parent);
            } else if (parent)
            {
                // the fake event path for an exited or kernel thread pretends that the
                // parent pid is 1. dont do this for systemd itself though
                parent = 1;
            }
        }

        // This will use the comm instead of a path
        procp = process_tracking_create_process(
                pid,
                parent,
                tid,
                uid,
                euid,
                start_time - 1, // important to avoid collision here
                CB_PROCESS_START_BY_FORK,
                taskp,
                FAKE_START,
                context);

        if (!procp)
        {
            TRACE(DL_PROC_TRACKING, "TRACK-UPD <FAKE> FAILED to create tracking entry for %d by %d",
                    pid,
                    parent);
            return NULL;
        }
    }

    // Increase the reference count on the shared data (for local function)
    parent_shared_data = process_tracking_get_shared_data_ref(procp->shared_data, context);

    isExecOther = parent_shared_data->exec_details.pid == pid;

    // The new process we are execing was an active process in its parent. So reduce the active count of the parent
    IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(&parent_shared_data->active_process_count, { was_last_active_process = true; });

    // If this is was the last remaining process of the exec identity we want to
    //  send an exit for it.
    //  This will catch exec-other and last fork cases.  We want to ignore a fake start however.
    if (was_last_active_process && is_real_start)
    {
        // Send the event based on the current process information.
        //  We will not delete the procp since it will be used by the new process.
        //  The shared_data will be released later
        event_send_exit(procp, was_last_active_process, context);
    }

    // Allocate a shared data_object for the new process
    //  We get a reference to this
    shared_data = process_tracking_alloc_shared_data(context);

    TRY_DO_MSG(shared_data,
               { procp = NULL; },
               DL_WARNING, "%s: error allocating shared data for pid[%d]\n", __func__, pid);

    // reported data changes generations during exec
    shared_data->exec_grandparent_details = parent_shared_data->exec_parent_details;
    shared_data->exec_parent_details      = parent_shared_data->exec_details;


    shared_data->exec_details.pid         = pid;
    shared_data->exec_details.device      = device;
    shared_data->exec_details.inode       = inode;
    shared_data->exec_details.start_time  = start_time;

    shared_data->path_found               = path_found;
    shared_data->exec_count               = (!isExecOther ? 1 : parent_shared_data->exec_count + 1);

    procp->posix_details.inode            = inode;
    procp->posix_details.device           = device;
    procp->posix_details.inode            = inode;

    if (!path && is_task_valid(taskp))
    {
        path = taskp->comm;
    }

    shared_data->path = cb_mem_cache_strdup(path, context);
    TRY(shared_data->path);

    shared_data->is_interpreter = process_tracking_is_interpreter(shared_data->path);

    // Update our table entry with the new shared data
    process_tracking_set_shared_data(procp, shared_data, context);

    // Mark us as an active process
    atomic64_inc(&shared_data->active_process_count);

    procp->tid            = tid;
    procp->uid            = uid;
    procp->euid           = euid;
    procp->action         = action;
    procp->is_real_start  = is_real_start;

    if (is_real_start)
    {
        // Hold onto a reference to our parent shared_data until the start event is sent.
        //  This will ensure the exit event of the parent is sent after this start event
        process_tracking_set_parent_shared_data(procp, parent_shared_data, context);
    }

    process_tracking_update_op_cnts(procp, event_type, action);

    TRACE(DL_PROC_TRACKING, "TRACK-UPD %s%s of %d by %d (reported as %d by %d) (active: %ld)",
          msg,
          (path ? path : "<unknown>"),
          pid,
          parent,
          shared_data->exec_details.pid,
          shared_data->exec_parent_details.pid,
          atomic64_read(&shared_data->active_process_count));

CATCH_DEFAULT:
    // Release the local ref held by this function
    process_tracking_release_shared_data_ref(shared_data, context);
    process_tracking_release_shared_data_ref(parent_shared_data, context);

    return procp;
}

void process_tracking_put_process(ProcessTracking *procp, ProcessContext *context)
{
    if (procp)
    {
        hashtbl_put_generic(g_process_tracking_data.table, procp, context);
    }
}

void process_tracking_remove_process(ProcessTracking *procp, ProcessContext *context)
{
    if (procp)
    {
        g_process_tracking_data.op_cnt += 1;
        g_process_tracking_data.exit += 1;

        TRACE(DL_PROC_TRACKING, "TRACK-DEL pid=%d opcnt=%llu create=%llu exit=%llu",
               procp->posix_details.pid,
               g_process_tracking_data.op_cnt,
               g_process_tracking_data.create,
               g_process_tracking_data.exit);

        // In the exec-other and some pid wrap cases this entry may not exist in
        //  hash table.  In this case, it will be a no-op.
        hashtbl_del_generic(g_process_tracking_data.table, procp, context);
    }
}

static ProcessTracking *process_tracking_add_process(ProcessTracking *procp, ProcessContext *context)
{
    if (hashtbl_add_generic(g_process_tracking_data.table, procp, context) < 0)
    {
        // This will free the procp regardless of the current ref count
        hashtbl_free_generic(g_process_tracking_data.table, procp, context);
        procp = NULL;
    }
    return procp;
}

bool process_tracking_report_exit(pid_t pid, ProcessContext *context)
{
    bool was_last_active_process = false;
    bool warn_on_negative_active_count = LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0);
    ProcessTracking *procp = process_tracking_get_process(pid, context);

    TRY(procp);

    // There's an issue with our 2.6 exit hook that results in two exit events
    // for the same process at the same time. This silently ignores the second event.
    IF_ATOMIC64_DEC_AND_TEST__TRY_NEG(&procp->shared_data->active_process_count,
                                { was_last_active_process = true; },
                                      warn_on_negative_active_count);

    event_send_exit(procp, was_last_active_process, context);
    process_tracking_remove_process(procp, context);
    process_tracking_put_process(procp, context);
    return true;

CATCH_DEFAULT:
    process_tracking_put_process(procp, context);
    return false;
}

ProcessTracking *
get_procinfo_and_create_process_start_if_needed(pid_t pid, const char *msg, ProcessContext *context)
{
    ProcessTracking *procp = NULL;

    procp = process_tracking_get_process(pid, context);
    if (!procp)
    {
        TRACE(DL_INFO, "%s pid=%d not tracked", msg, pid);
        create_process_start_by_exec_event(current, context);
        procp = process_tracking_get_process(pid, context);
    }
    return procp;
}

void create_process_start_by_exec_event(struct task_struct *task, ProcessContext *context)
{
    uint64_t device = 0;
    uint64_t inode = 0;
    time_t start_time = get_current_time();
    uid_t uid = 0;
    uid_t euid = 0;
    pid_t pid = 0;
    pid_t tid = 0;

    char *path = NULL;
    bool path_found = false;
    ProcessTracking *procp = NULL;
    char *path_buffer = NULL;

    CANCEL_VOID_MSG(task, DL_WARNING, "cannot create process start with null task");

    uid = TASK_UID(task);
    euid = TASK_EUID(task);
    pid = getpid(task);
    tid = gettid(task);

    // PSCLNX-5220
    //  If we are in the clone hook it is possible for the task_get_path functon
    //  to schedule. (Softlock!)  For now I am catching this here and just useing
    //  the command name.  I want to make the decision down in task_get_path, but
    //  I need to pass the context.  (Which is too invasive for right now!)
    //
    //  Also this would need to be able to understand when we would be looking up
    //  the path for a task not our own.
    if (!ALLOW_WAKE_UP(context))
    {
        path = task->comm;
    } else
    {
        path_buffer = get_path_buffer(context);
        if (path_buffer)
        {
            // task_get_path() uses dpath which builds the path efficently
            //  by walking back to the root. It starts with a string terminator
            //  in the last byte of the target buffer.
            //
            // The `path` variable will point to the start of the string, so we will
            //  use that directly later to copy into the tracking entry and event.
            path_found = task_get_path(task, path_buffer, PATH_MAX, &path);
            path_buffer[PATH_MAX] = 0;

            if (!path_found)
            {
                TRACE(DL_INFO, "Failed to retrieve path for pid: %d", pid);
            }
        }
    }

    get_devinfo_from_task(task, &device, &inode);

    procp = process_tracking_update_process(
        pid,
        tid,
        uid,
        euid,
        device,
        inode,
        path,
        path_found,
        start_time,
        CB_PROCESS_START_BY_EXEC,
        task,
        CB_EVENT_TYPE_PROCESS_START_EXEC,
        FAKE_START,
        context);

    put_path_buffer(path_buffer);
    path = path_buffer = NULL;

    CANCEL_VOID(procp);

    event_send_start(procp,
                    process_tracking_should_track_user() ? uid : (uid_t)-1,
                    CB_PROCESS_START_BY_EXEC,
                    context);

    process_tracking_put_process(procp, context);
}

static SharedTrackingData *process_tracking_alloc_shared_data(ProcessContext *context)
{
    SharedTrackingData *shared_data = NULL;

    shared_data = (SharedTrackingData *)cb_mem_cache_alloc(&g_process_tracking_data.shared_data_cache, context);
    process_tracking_init_shared_data(shared_data, context);
    return process_tracking_get_shared_data_ref(shared_data, context);
}

static void process_tracking_init_shared_data(SharedTrackingData *shared_data, ProcessContext *context)
{
    if (shared_data)
    {
        file_process_tree_init(&shared_data->tracked_files, context);
        atomic64_set(&shared_data->reference_count, 0);
        atomic64_set(&shared_data->active_process_count, 0);
        atomic64_set(&shared_data->exit_event, 0);
        shared_data->path               = NULL;
        shared_data->cmdline            = NULL;
        shared_data->is_interpreter     = false;
    }
}

void process_tracking_release_shared_data_ref(SharedTrackingData *shared_data, ProcessContext *context)
{
    PCB_EVENT exit_event;

    CANCEL_VOID(shared_data);

    TRACE_IF_REF_DEBUGGING(DL_PROC_TRACKING, "    %s: %s %d shared_data Ref count: %ld/%ld (%p)",
        __func__,
        process_tracking_get_proc_name(shared_data->path),
        shared_data->exec_details.pid,
        atomic64_read(&shared_data->reference_count),
        atomic64_read(&shared_data->active_process_count),
        shared_data);

    // If the reference count reaches 0, then delete it
    IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(&shared_data->reference_count, {
        // Notify the file tracking logic that this process has exited and any open files should be purged.
        check_open_file_list_on_exit(shared_data->tracked_files, context);

        // Destroy the file tracking
        file_process_tree_destroy(&shared_data->tracked_files, context);

        // Free the path and commandline
        cb_mem_cache_free_generic(shared_data->path);
        cb_mem_cache_free_generic(shared_data->cmdline);

        exit_event = (PCB_EVENT) atomic64_xchg(&shared_data->exit_event, 0);

        // Send the exit
        event_send_last_exit(exit_event, context);

        shared_data->path       = NULL;
        shared_data->cmdline    = NULL;

        // Free the shared data
        cb_mem_cache_free(&g_process_tracking_data.shared_data_cache, shared_data, context);
    });
}

// Note: This function is used as a callback by the generic hash table to
//  delete our private data.
static void hashtbl_delete_callback(void *data, ProcessContext *context)
{
    if (data)
    {
        ProcessTracking *procp = (ProcessTracking *)data;

        if (g_print_proc_on_delete && procp)
        {
            TRACE(DL_INFO, "    %s: %s %d shared_data Ref count: %ld/%ld (%p)",
                                   __func__,
                                   process_tracking_get_proc_name(procp->shared_data->path),
                                   procp->shared_data->exec_details.pid,
                                   atomic64_read(&(procp->shared_data->reference_count)),
                                   atomic64_read(&(procp->shared_data->active_process_count)),
                                   procp->shared_data);
        }

        process_tracking_set_shared_data(procp, NULL, context);
        process_tracking_set_parent_shared_data(procp, NULL, context);
    }
}

// Note: This function is used as a callback by the cb-mem-cache to print any
// kmem cache entries that are still alive when the cache is destroyed.
static void shareddata_print_callback(void *data, ProcessContext *context)
{
    if (data)
    {
        SharedTrackingData *sdata = (SharedTrackingData *)data;

        TRACE(DL_INFO, "    %s: %s %d shared_data Ref count: %ld/%ld (%p)",
              __func__,
              process_tracking_get_proc_name(sdata->path),
              sdata->exec_details.pid,
              atomic64_read(&(sdata->reference_count)),
              atomic64_read(&(sdata->active_process_count)),
              sdata);
    }
}
