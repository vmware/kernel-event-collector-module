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

void ec_hashtbl_delete_callback(void *posix_identity, ProcessContext *context);
void __ec_exec_identity_print_callback(void *data, ProcessContext *context);

ExecIdentity *ec_process_tracking_alloc_exec_identity(ProcessContext *context);
void ec_process_tracking_init_exec_identity(ExecIdentity *exec_identity, ProcessContext *context);
PosixIdentity *ec_process_tracking_add_process(PosixIdentity *posix_identity, ProcessContext *context);

process_tracking_data g_process_tracking_data = { 0, };

// TODO set this list dynamically via ioctl
// For now, the interpreter list is set from this static array.
char  *static_interpreter_names[] = {
    "bash", "sh", "csh", "zsh", "ksh", "perl", "python", "ruby", "java", "js", "node", "firefox", "chrome", "lua",
    "php", "tcl", "dash", "pwsh", "env"};
char **g_interpreter_names = static_interpreter_names;
int    g_interpreter_names_count = sizeof(static_interpreter_names)/sizeof(char *);

bool g_print_proc_on_delete;

#define CB_PT_CACHE_OBJ_SZ  256

bool ec_process_tracking_should_track_user(void)
{
    return g_driver_config.report_process_user == ENABLE;
}

bool ec_process_tracking_initialize(ProcessContext *context)
{
    g_print_proc_on_delete = false;
    g_process_tracking_data.table = ec_hashtbl_init_generic(
                                                    context,
                                                    8192,
                                                    sizeof(PosixIdentity),
                                                    CB_PT_CACHE_OBJ_SZ,
                                                    "pt_cache",
                                                    sizeof(PT_TBL_KEY),
                                                    offsetof(PosixIdentity, pt_key),
                                                    offsetof(PosixIdentity, pt_link),
                                                    offsetof(PosixIdentity, reference_count),
                                                    ec_hashtbl_delete_callback);
    TRY(g_process_tracking_data.table);

    TRY(ec_mem_cache_create(&g_process_tracking_data.exec_identity_cache, "pt_exec_identity_cache", sizeof(ExecIdentity), context));

    return true;

CATCH_DEFAULT:
    ec_process_tracking_shutdown(context);
    return false;
}

void ec_process_tracking_shutdown(ProcessContext *context)
{
    g_print_proc_on_delete = true;

    if (g_process_tracking_data.table)
    {
        ec_hashtbl_shutdown_generic(g_process_tracking_data.table, context);
        g_process_tracking_data.table = NULL;
    }

    ec_mem_cache_destroy(&g_process_tracking_data.exec_identity_cache, context, __ec_exec_identity_print_callback);

    g_print_proc_on_delete = false;
}

PosixIdentity *ec_process_tracking_get_process(pid_t pid, ProcessContext *context)
{
    PT_TBL_KEY key = { pid };

    PosixIdentity *posix_identity = ((PosixIdentity *)ec_hashtbl_get_generic(g_process_tracking_data.table, &key, context));

    return posix_identity;
}

// Check whether path points at an interpreter.
bool ec_process_tracking_is_interpreter(ExecIdentity *exec_identity, ProcessContext *context)
{
    bool result = false;
    char *path = ec_process_tracking_get_path(exec_identity, context);

    if (path)
    {
        const char *proc_name = ec_process_tracking_get_proc_name(path);
        int i;

        for (i = 0; i < g_interpreter_names_count; i++)
        {
            char *found = strstr(proc_name, g_interpreter_names[i]);
            // Does process filename start with the interpreter name? This includes e.g. python3/perl5 but
            // does not include every filename containing 'sh' anywhere, e.g. ssh
            if (found && found == proc_name)
            {
                result = true;
                break;
            }
        }
    }
    ec_process_tracking_put_path(path, context);

    return result;
}

PosixIdentity *ec_process_tracking_create_process(
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
    PosixIdentity    *posix_identity        = NULL;
    ExecIdentity *exec_identity  = NULL;
    PosixIdentity    *parent_posix_identity = NULL;
    char               *msg          = (is_real_start ? "" : "<FAKE> ");
    ProcessDetails      posix_parent_details      = { 0 };
    ProcessDetails      posix_grandparent_details = { 0 };

    // If this start is a fork we need to pull the shared struct from the parent
    if (action == CB_PROCESS_START_BY_FORK)
    {
        parent_posix_identity = ec_process_tracking_get_process(parent, context);
        if (parent_posix_identity)
        {
            // Increase the reference count on the shared data (for local function)
            exec_identity = ec_process_tracking_get_exec_identity(parent_posix_identity, context);
            posix_parent_details      = parent_posix_identity->posix_details;
            posix_grandparent_details = parent_posix_identity->posix_parent_details;

            ec_process_tracking_put_process(parent_posix_identity, context);
        }
    }

    // We don't have a exec_identity object from our parent, so create one now.  This
    //  will happen in three cases.
    //  1. We observed some event on this process
    //  2. We saw a fork, but the parent is not tracked
    //  3. We saw an exec on this process
    if (!exec_identity)
    {
        struct task_struct *parent_task  = (taskp       ? taskp->real_parent : NULL);
        struct task_struct *gparent_task = (parent_task ? parent_task->real_parent : NULL);

        // TODO: We really need to build my parent
        // This gives us a local reference
        exec_identity = ec_process_tracking_alloc_exec_identity(context);
        if (!exec_identity)
        {
            return NULL;
        }

        exec_identity->exec_details.pid                = parent;
        exec_identity->exec_details.start_time         = start_time;
        ec_get_devinfo_from_task(taskp, &exec_identity->exec_details.device, &exec_identity->exec_details.inode);

        exec_identity->exec_parent_details.pid         = (gparent_task ? ec_getpid(gparent_task) : 1);
        exec_identity->exec_parent_details.start_time  = ec_get_null_time();
        ec_get_devinfo_from_task(parent_task, &exec_identity->exec_details.device, &exec_identity->exec_details.inode);

        exec_identity->exec_grandparent_details.pid         = 0;
        exec_identity->exec_grandparent_details.device      = 0;
        exec_identity->exec_grandparent_details.inode       = 0;
        exec_identity->exec_grandparent_details.start_time  = ec_get_null_time();

        exec_identity->path_found   = false;
        exec_identity->exec_count   = 1;

        posix_parent_details      = exec_identity->exec_details;
        posix_grandparent_details = exec_identity->exec_parent_details;

        exec_identity->is_interpreter = ec_process_tracking_is_interpreter(exec_identity, context);
    }

    posix_identity = (PosixIdentity *)ec_hashtbl_alloc_generic(g_process_tracking_data.table, context);
    if (posix_identity)
    {
        posix_identity->pt_key.pid                 = pid;
        posix_identity->tid                        = tid;
        posix_identity->uid                        = uid;
        posix_identity->euid                       = euid;
        posix_identity->action                     = action;
        posix_identity->process_op_cnt             =
            posix_identity->process_create         =
            posix_identity->process_create_by_fork =
            posix_identity->process_create_by_exec =
            posix_identity->childproc_cnt          =
            posix_identity->file_op_cnt            =
            posix_identity->file_map_exec          =
            posix_identity->file_create            =
            posix_identity->file_delete            =
            posix_identity->file_open              =
            posix_identity->file_write             =
            posix_identity->file_close             =
            posix_identity->net_op_cnt             =
            posix_identity->net_connect            =
            posix_identity->net_accept             =
            posix_identity->net_dns                = 0;
        posix_identity->is_real_start              = is_real_start;
        posix_identity->exec_identity                = NULL;
        posix_identity->temp_exec_identity           = NULL;
        posix_identity->exec_blocked               = false;

        posix_identity->posix_details.pid         = pid;
        posix_identity->posix_details.device      = exec_identity->exec_details.device;
        posix_identity->posix_details.inode       = exec_identity->exec_details.inode;
        posix_identity->posix_details.start_time  = start_time;

        posix_identity->posix_parent_details      = posix_parent_details;
        posix_identity->posix_grandparent_details = posix_grandparent_details;
        atomic64_set(&posix_identity->reference_count, 1);

        g_process_tracking_data.op_cnt += 1;
        g_process_tracking_data.create += 1;

        if (action == CB_PROCESS_START_BY_FORK)
        {
            g_process_tracking_data.create_by_fork += 1;
        } else if (action == CB_PROCESS_START_BY_EXEC)
        {
            g_process_tracking_data.create_by_exec += 1;
        }

        ec_process_tracking_set_exec_identity(posix_identity, exec_identity, context);

        posix_identity = ec_process_tracking_add_process(posix_identity, context);
        TRY(posix_identity);


        // We have recorded this in the tracking table, so mark it as active
        atomic64_inc(&exec_identity->active_process_count);

        if (MAY_TRACE_LEVEL(DL_PROC_TRACKING))
        {
            char *path = ec_process_tracking_get_path(exec_identity, context);

            TRACE(DL_PROC_TRACKING, "TRACK-INS %s%s of %d by %d (reported as %d by %d) (active: %" PRFs64 ")",
                  msg,
                  path,
                  pid,
                  parent,
                  exec_identity->exec_details.pid,
                  exec_identity->exec_parent_details.pid,
                  (long long) atomic64_read(&exec_identity->active_process_count));
            ec_process_tracking_put_path(path, context);
        }
    }

CATCH_DEFAULT:
    // Always drop the ref held by this local function
    ec_process_tracking_put_exec_identity(exec_identity, context);

    return posix_identity;
}

PosixIdentity *ec_process_tracking_update_process(
    pid_t               pid,
    pid_t               tid,
    uid_t               uid,
    uid_t               euid,
    uint64_t            device,
    uint64_t            inode,
    char               *path,
    bool                path_found,
    time_t              start_time,
    int                 action,
    struct task_struct *taskp,
    CB_EVENT_TYPE       event_type,
    bool                is_real_start,
    ProcessContext     *context)
{
    PosixIdentity    *posix_identity              = NULL;
    ExecIdentity *exec_identity        = NULL;
    ExecIdentity *parent_exec_identity = NULL;
    pid_t               parent             = ec_getppid(taskp);
    struct task_struct *parent_task        = (taskp       ? taskp->real_parent : NULL);
    char               *msg                = "";
    bool isExecOther = false;
    bool was_last_active_process = false;

    posix_identity = ec_process_tracking_get_process(pid, context);
    if (!posix_identity)
    {
        msg = "<FAKE> ";

        if (!ec_is_process_tracked(parent, context))
        {
            if (ec_is_task_valid(parent_task) && parent_task->mm)
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
        posix_identity = ec_process_tracking_create_process(
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

        if (!posix_identity)
        {
            TRACE(DL_PROC_TRACKING, "TRACK-UPD <FAKE> FAILED to create tracking entry for %d by %d",
                    pid,
                    parent);
            return NULL;
        }
    }

    // Increase the reference count on the shared data (for local function)
    parent_exec_identity = ec_process_tracking_get_exec_identity(posix_identity, context);

    isExecOther = parent_exec_identity->exec_details.pid == pid;

    // The new process we are execing was an active process in its parent. So reduce the active count of the parent
    IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(&parent_exec_identity->active_process_count, { was_last_active_process = true; });

    // Allocate a shared data_object for the new process
    //  We get a reference to this
    exec_identity = ec_process_tracking_alloc_exec_identity(context);

    // If this is was the last remaining process of the exec identity we want to
    //  send an exit for it.
    //  This will catch exec-other and last fork cases.  We want to ignore a fake start however.
    if (was_last_active_process && is_real_start)
    {
        // This will set the current proc's temp_exec_identity to the new shared data of the execed proc.
        // The exit event (for the previous exec identity/parent) will take a reference to this exec_identity.
        // This forces the new exec's exit event to wait to be queued until after previous exec's exit event.
        ec_process_tracking_set_temp_exec_identity(posix_identity, exec_identity, context);

        // Send the event based on the current process information.
        //  We will not delete the posix_identity since it will be used by the new process.
        //  The exec_identity will be released later
        ec_event_send_exit(posix_identity, was_last_active_process, context);
    }

    TRY_DO_MSG(exec_identity,
               { posix_identity = NULL; },
               DL_WARNING, "%s: error allocating shared data for pid[%d]\n", __func__, pid);

    // reported data changes generations during exec
    exec_identity->exec_grandparent_details = parent_exec_identity->exec_parent_details;
    exec_identity->exec_parent_details      = parent_exec_identity->exec_details;


    exec_identity->exec_details.pid         = pid;
    exec_identity->exec_details.device      = device;
    exec_identity->exec_details.inode       = inode;
    exec_identity->exec_details.start_time  = start_time;

    exec_identity->path_found               = path_found;
    exec_identity->exec_count               = (!isExecOther ? 1 : parent_exec_identity->exec_count + 1);

    posix_identity->posix_details.inode            = inode;
    posix_identity->posix_details.device           = device;
    posix_identity->posix_details.inode            = inode;

    if (!path && ec_is_task_valid(taskp))
    {
        path = taskp->comm;
    }

    path = ec_mem_cache_strdup(path, context);

    TRY(path);
    ec_process_tracking_set_path(exec_identity, path, context);

    exec_identity->is_interpreter = ec_process_tracking_is_interpreter(exec_identity, context);

    // Update our table entry with the new shared data
    ec_process_tracking_set_exec_identity(posix_identity, exec_identity, context);

    // Mark us as an active process
    atomic64_inc(&exec_identity->active_process_count);

    posix_identity->tid            = tid;
    posix_identity->uid            = uid;
    posix_identity->euid           = euid;
    posix_identity->action         = action;
    posix_identity->is_real_start  = is_real_start;

    if (is_real_start)
    {
        // Hold onto a reference to our parent exec_identity until the start event is sent.
        //  This will ensure the exit event of the parent is sent after this start event
        ec_process_tracking_set_temp_exec_identity(posix_identity, parent_exec_identity, context);
    }

    ec_process_tracking_update_op_cnts(posix_identity, event_type, action);

    if (MAY_TRACE_LEVEL(DL_PROC_TRACKING))
    {
        TRACE(DL_PROC_TRACKING, "TRACK-UPD %s%s of %d by %d (reported as %d:%ld by %d:%ld) (active: %" PRFs64 ")",
              msg,
              path ? path : "<unknown>",
              pid,
              parent,
              exec_identity->exec_details.pid,
              exec_identity->exec_details.start_time,
              exec_identity->exec_parent_details.pid,
              exec_identity->exec_parent_details.start_time,
              (long long)atomic64_read(&exec_identity->active_process_count));
    }

CATCH_DEFAULT:
    // Release the local ref held by this function
    ec_process_tracking_put_path(path, context);
    ec_process_tracking_put_exec_identity(exec_identity, context);
    ec_process_tracking_put_exec_identity(parent_exec_identity, context);

    return posix_identity;
}

void ec_process_tracking_put_process(PosixIdentity *posix_identity, ProcessContext *context)
{
    if (posix_identity)
    {
        ec_hashtbl_put_generic(g_process_tracking_data.table, posix_identity, context);
    }
}

void ec_process_tracking_remove_process(PosixIdentity *posix_identity, ProcessContext *context)
{
    if (posix_identity)
    {
        g_process_tracking_data.op_cnt += 1;
        g_process_tracking_data.exit += 1;

        TRACE(DL_PROC_TRACKING, "TRACK-DEL pid=%d opcnt=%llu create=%llu exit=%llu",
               posix_identity->posix_details.pid,
               g_process_tracking_data.op_cnt,
               g_process_tracking_data.create,
               g_process_tracking_data.exit);

        // In the exec-other and some pid wrap cases this entry may not exist in
        //  hash table.  In this case, it will be a no-op.
        ec_hashtbl_del_generic(g_process_tracking_data.table, posix_identity, context);
    }
}

PosixIdentity *ec_process_tracking_add_process(PosixIdentity *posix_identity, ProcessContext *context)
{
    if (ec_hashtbl_add_generic(g_process_tracking_data.table, posix_identity, context) < 0)
    {
        // This will free the posix_identity regardless of the current ref count
        ec_hashtbl_free_generic(g_process_tracking_data.table, posix_identity, context);
        posix_identity = NULL;
    }
    return posix_identity;
}

bool ec_process_tracking_report_exit(pid_t pid, ProcessContext *context)
{
    bool result = false;
    bool was_last_active_process = false;
    PosixIdentity *posix_identity = ec_process_tracking_get_process(pid, context);
    ExecIdentity *exec_identity = ec_process_tracking_get_exec_identity(posix_identity, context);

    TRY(posix_identity && exec_identity);

    IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(&exec_identity->active_process_count, { was_last_active_process = true; });

    ec_event_send_exit(posix_identity, was_last_active_process, context);
    ec_process_tracking_remove_process(posix_identity, context);
    result = true;

CATCH_DEFAULT:
    ec_process_tracking_put_exec_identity(exec_identity, context);
    ec_process_tracking_put_process(posix_identity, context);
    return result;
}

PosixIdentity *ec_get_procinfo_and_create_process_start_if_needed(pid_t pid, const char *msg, ProcessContext *context)
{
    PosixIdentity *posix_identity = NULL;

    posix_identity = ec_process_tracking_get_process(pid, context);
    if (!posix_identity)
    {
        TRACE(DL_INFO, "%s pid=%d not tracked", msg, pid);
        ec_create_process_start_by_exec_event(current, context);
        posix_identity = ec_process_tracking_get_process(pid, context);
    }
    return posix_identity;
}

void ec_create_process_start_by_exec_event(struct task_struct *task, ProcessContext *context)
{
    uint64_t device = 0;
    uint64_t inode = 0;
    time_t start_time = ec_get_current_time();
    uid_t uid = 0;
    uid_t euid = 0;
    pid_t pid = 0;
    pid_t tid = 0;

    char *path = NULL;
    bool path_found = false;
    PosixIdentity *posix_identity = NULL;
    char *path_buffer = NULL;

    CANCEL_VOID_MSG(task, DL_WARNING, "cannot create process start with null task");

    uid = TASK_UID(task);
    euid = TASK_EUID(task);
    pid = ec_getpid(task);
    tid = ec_gettid(task);

    // PSCLNX-5220
    //  If we are in the clone hook it is possible for the ec_task_get_path functon
    //  to schedule. (Softlock!)  For now I am catching this here and just useing
    //  the command name.  I want to make the decision down in ec_task_get_path, but
    //  I need to pass the context.  (Which is too invasive for right now!)
    //
    //  Also this would need to be able to understand when we would be looking up
    //  the path for a task not our own.
    if (!ALLOW_WAKE_UP(context))
    {
        path = task->comm;
    } else
    {
        path_buffer = ec_get_path_buffer(context);
        if (path_buffer)
        {
            // ec_task_get_path() uses dpath which builds the path efficently
            //  by walking back to the root. It starts with a string terminator
            //  in the last byte of the target buffer.
            //
            // The `path` variable will point to the start of the string, so we will
            //  use that directly later to copy into the tracking entry and event.
            path_found = ec_task_get_path(task, path_buffer, PATH_MAX, &path);
            path_buffer[PATH_MAX] = 0;

            if (!path_found)
            {
                TRACE(DL_INFO, "Failed to retrieve path for pid: %d", pid);
            }
        }
    }

    ec_get_devinfo_from_task(task, &device, &inode);

    posix_identity = ec_process_tracking_update_process(
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

    ec_put_path_buffer(path_buffer);
    path = path_buffer = NULL;

    CANCEL_VOID(posix_identity);

    ec_event_send_start(posix_identity,
                    ec_process_tracking_should_track_user() ? uid : (uid_t)-1,
                    CB_PROCESS_START_BY_EXEC,
                    context);

    ec_process_tracking_put_process(posix_identity, context);
}

ExecIdentity *ec_process_tracking_alloc_exec_identity(ProcessContext *context)
{
    ExecIdentity *exec_identity = NULL;

    exec_identity = (ExecIdentity *)ec_mem_cache_alloc(&g_process_tracking_data.exec_identity_cache, context);
    ec_process_tracking_init_exec_identity(exec_identity, context);
    return ec_process_tracking_get_exec_identity_ref(exec_identity, context);
}

void ec_process_tracking_init_exec_identity(ExecIdentity *exec_identity, ProcessContext *context)
{
    if (exec_identity)
    {
        ec_file_process_tree_init(&exec_identity->tracked_files, context);
        atomic64_set(&exec_identity->reference_count, 0);
        atomic64_set(&exec_identity->active_process_count, 0);
        atomic64_set(&exec_identity->exit_event, 0);
        exec_identity->path               = NULL;
        exec_identity->cmdline            = NULL;
        exec_identity->is_interpreter     = false;

        // TODO: Add lock here
    }
}

void ec_process_tracking_put_exec_identity(ExecIdentity *exec_identity, ProcessContext *context)
{
    PCB_EVENT exit_event;

    CANCEL_VOID(exec_identity);

    #ifdef _REF_DEBUGGING
    if (MAY_TRACE_LEVEL(DL_PROC_TRACKING))
    {
        char *path = ec_process_tracking_get_path(exec_identity, context);

        TRACE(DL_PROC_TRACKING, "    %s: %s %d exec_identity Ref count: %" PRFs64 "/%" PRFs64 " (%p)",
            __func__,
            ec_process_tracking_get_proc_name(path),
            exec_identity->exec_details.pid,
            (long long)atomic64_read(&exec_identity->reference_count),
            (long long)atomic64_read(&exec_identity->active_process_count),
            exec_identity);
        ec_process_tracking_put_path(path, context);
    }
    #endif

    // If the reference count reaches 0, then delete it
    IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(&exec_identity->reference_count, {
        // Notify the file tracking logic that this process has exited and any open files should be purged.
        ec_check_open_file_list_on_exit(exec_identity->tracked_files, context);

        // Destroy the file tracking
        ec_file_process_tree_destroy(&exec_identity->tracked_files, context);


        // Free the path and commandline
        ec_process_tracking_set_path(exec_identity, NULL, context);
        ec_process_tracking_set_cmdline(exec_identity, NULL, context);

        exit_event = (PCB_EVENT) atomic64_xchg(&exec_identity->exit_event, 0);

        // Send the exit
        ec_event_send_last_exit(exit_event, context);

        // TODO: Add lock here

        // Free the shared data
        ec_mem_cache_free(&g_process_tracking_data.exec_identity_cache, exec_identity, context);
    });
}

// Note: This function is used as a callback by the generic hash table to
//  delete our private data.
void ec_hashtbl_delete_callback(void *data, ProcessContext *context)
{
    if (data)
    {
        PosixIdentity *posix_identity = (PosixIdentity *)data;

        if (g_print_proc_on_delete && posix_identity && MAY_TRACE_LEVEL(DL_INFO))
        {
            ExecIdentity *exec_identity = ec_process_tracking_get_exec_identity(posix_identity, context);
            char *path = ec_process_tracking_get_path(exec_identity, context);

            if (exec_identity)
            {
                TRACE(DL_INFO, "    %s: %s %d exec_identity Ref count: %" PRFs64 "/%" PRFs64 " (%p)",
                      __func__,
                      ec_process_tracking_get_proc_name(path),
                      exec_identity->exec_details.pid,
                      (long long) atomic64_read(&(exec_identity->reference_count)),
                      (long long) atomic64_read(&(exec_identity->active_process_count)),
                      exec_identity);
            }
            ec_process_tracking_put_path(path, context);
            ec_process_tracking_put_exec_identity(exec_identity, context);
        }

        ec_process_tracking_set_exec_identity(posix_identity, NULL, context);
        // Just in case, this should have been unset by ec_process_tracking_set_event_info
        ec_process_tracking_set_temp_exec_identity(posix_identity, NULL, context);
    }
}

// Note: This function is used as a callback by the cb-mem-cache to print any
// kmem cache entries that are still alive when the cache is destroyed.
void __ec_exec_identity_print_callback(void *data, ProcessContext *context)
{
    if (data && MAY_TRACE_LEVEL(DL_INFO))
    {
        ExecIdentity *exec_identity = (ExecIdentity *)data;
        char *path = ec_process_tracking_get_path(exec_identity, context);

        TRACE(DL_INFO, "    %s: %s %d exec_identity Ref count: %" PRFs64 "/%" PRFs64 " (%p)",
              __func__,
              ec_process_tracking_get_proc_name(path),
              exec_identity->exec_details.pid,
              (long long)atomic64_read(&(exec_identity->reference_count)),
              (long long)atomic64_read(&(exec_identity->active_process_count)),
              exec_identity);
        ec_process_tracking_put_path(path, context);
    }
}
