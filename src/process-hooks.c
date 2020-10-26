// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/binfmts.h>
#include <linux/cred.h>
#endif
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <trace/events/sched.h>

#include "process-tracking.h"
#include "cb-banning.h"
#include "event-factory.h"
#include "path-buffers.h"
#include "cb-spinlock.h"
#include "task-helper.h"

static void cb_exit_hook(struct task_struct *task, ProcessContext *context);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    static void sched_process_fork_probe(void *data, struct task_struct *parent, struct task_struct *child);
#else
    static void sched_process_fork_probe(struct task_struct *parent, struct task_struct *child);
#endif

bool task_initialize(ProcessContext *context)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    register_trace_sched_process_fork(sched_process_fork_probe, NULL);
#else
    register_trace_sched_process_fork(sched_process_fork_probe);
#endif

    return true;
}

void task_shutdown(ProcessContext *context)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    unregister_trace_sched_process_fork(sched_process_fork_probe, NULL);
#else
    unregister_trace_sched_process_fork(sched_process_fork_probe);
#endif
}

// RHEL 7 has an optomized code path for exits when a process can not be reaped.
//  In this case the `task_wait` hook is not called.  This causes us to miss exit
//  events, and leak process tracking entires.
//
// For RHEL 7 we can switch to using the `task_free` hook, but this is not available
//  on RHEL 6.  However RHEL 6 does not appear to have this issue, so we will
//  continue to use the `task_wait` hook.
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    int cb_task_wait(struct task_struct *task)
    {
        int              ret;

        // This is in the kernel exit code, I don't know if it is safe to be NON_ATOMIC
        DECLARE_ATOMIC_CONTEXT(context, task ? getpid(task) : 0);

        MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);
        TRY(task);

        if (task->state == TASK_DEAD || task->exit_state == EXIT_DEAD)
        {
            cb_exit_hook(task, &context);
        }

CATCH_DEFAULT:
        ret = g_original_ops_ptr->task_wait(task);
        MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
        return ret;
    }
#else
    void cb_task_free(struct task_struct *task)
    {
        // This is in the kernel exit code, I don't know if it is safe to be NON_ATOMIC
        DECLARE_ATOMIC_CONTEXT(context, task ? getpid(task) : 0);

        MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);
        TRY(task);

        cb_exit_hook(task, &context);

CATCH_DEFAULT:
        g_original_ops_ptr->task_free(task);
        MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    }
#endif /* KERNEL_VERSION CHECK */

static void cb_exit_hook(struct task_struct *task, ProcessContext *context)
{
    pid_t pid = getpid(task);

    // If the `pid` and `tid` are the same than this is a fork.  If they are different this is a
    //  thread.  We need to ignore threads.
    // In theory we should see `CLONE_THREAD` in flags, but I have often found this to be garbage data.
    CANCEL_VOID(gettid(task) == pid);

    // disconnect_reader will do nothing if the pid isn't the reader process.
    // Otherwise, it will disconnect the reader which we need if it exits without
    // releasing the devnode.
    if (disconnect_reader(pid))
    {
        TRACE(DL_INFO, "reader process has exited, and has been disconnected; pid=%d", pid);
    }

    CANCEL_VOID(!cbIgnoreProcess(context, pid));

    CANCEL_VOID_MSG(process_tracking_report_exit(pid, context),
        DL_PROC_TRACKING, "remove process failed to find pid=%d\n", pid);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
void sched_process_fork_probe(void *data, struct task_struct *parent, struct task_struct *child)
#else
void sched_process_fork_probe(struct task_struct *parent, struct task_struct *child)
#endif
{
    DECLARE_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // ignore kernel tasks (swapper, migrate, etc)
    // this is critial because path lookups for these functions will schedule
    // and deadlock the system
    TRY(child->mm != NULL);

    // only hook for tasks which are new and have not yet run
    TRY(child->se.sum_exec_runtime == 0);

    // Do not allow any calls to schedule tasks
    DISABLE_WAKE_UP(&context);

    cb_clone_hook(&context, child);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
}

void cb_clone_hook(ProcessContext *context, struct task_struct *task)
{
    // this function is called after the task is created but before it has been
    // allowed to run.
    // also the disable logic is owned by the wapper in cfs.c

    pid_t tid = gettid(task);
    pid_t pid = getpid(task);
    pid_t ppid = getppid(task);
    uid_t uid = TASK_UID(task);
    uid_t euid = TASK_EUID(task);
    struct timespec start_time = {0};
    ProcessTracking *procp = NULL;

    getnstimeofday(&start_time);

    // If the `pid` and `tid` are the same than this is a fork.  If they are different this is a
    //  thread.  We need to ignore threads.
    // In theory we should see `CLONE_THREAD` in flags, but I have often found this to be garbage data.
    if (gettid(task) != getpid(task))
    {
        return;
    }

    // It is not safe to allow scheduling in this hook
    if (is_process_tracked(pid, context))
    {
        TRACE(DL_PROC_TRACKING, "fork hook called on already tracked pid=%d", pid);
        return;
    }

    if (!is_process_tracked(ppid, context))
    {
        // in some rare cases during startup we can still get into a position where
        // the parent is not in the tracking table. if this is the case we insert it and
        // send a fake process-start

        TRACE(DL_PROC_TRACKING, "fork ppid=%d not tracked", ppid);
        create_process_start_by_exec_event(task->real_parent, context);
    }

    procp = process_tracking_create_process(
        pid,
        ppid,
        tid,
        uid,
        euid,
        to_windows_timestamp(&start_time),
        CB_PROCESS_START_BY_FORK,
        task,
        REAL_START,
        context);

    // Send the event
    event_send_start(procp,
                    process_tracking_should_track_user() ? uid : (uid_t)-1,
                    CB_PROCESS_START_BY_FORK,
                    context);

    process_tracking_put_process(procp, context);
}

// This hook happens before the exec.  It will handle both the banning case and the start case
//  Note: We used to handle the start in a post hook.  We are using the pre hook for two reasons.
//        1. We had problems with page faults in the post hook
//        2. We need the process tracking entry to be updated for the baned event anyway
int cb_bprm_check_security(struct linux_binprm *bprm)
{
    struct task_struct *task = current;
    pid_t pid = getpid(task);
    pid_t tid = gettid(task);
    uid_t uid = GET_UID();
    uid_t euid = GET_EUID();
    struct timespec start_time = {0, 0};
    ProcessTracking *procp = NULL;
    uint64_t device = 0;
    uint64_t inode = 0;
    char *path_buffer = NULL;
    char *path = NULL;
    bool path_found = false;
    int stat = 0;
    bool killit = false;
    int ret = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, pid);

    MODULE_GET();

    // get time as early in the function as possible
    getnstimeofday(&start_time);

    // Call any other hooks in the chain, and bail if they want to bail
    ret = g_original_ops_ptr->bprm_check_security(bprm);
    TRY(ret == 0);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY(!cbIgnoreProcess(&context, pid));

    // Check the current creds, this may tell us we are supposed to bail
    stat = g_original_ops_ptr->bprm_set_creds(bprm);

    get_devinfo_from_file(bprm->file, &device, &inode);

    if (tid != INITTASK)
    {
        killit = cbKillBannedProcessByInode(&context, device, inode);
    }

    // get a temporary path buffer before going into an unschedulable state
    // It is safe to schedule in this hook
    path_buffer = get_path_buffer(&context);
    if (path_buffer)
    {
        // file_get_path() uses dpath which builds the path efficently
        //  by walking back to the root. It starts with a string terminator
        //  in the last byte of the target buffer.
        //
        // The `path` variable will point to the start of the string, so we will
        //  use that directly later to copy into the tracking entry and event.
        path_found = file_get_path(bprm->file, path_buffer, PATH_MAX, &path);
        path_buffer[PATH_MAX] = 0;

        if (!path_found)
        {
            TRACE(DL_INFO, "Failed to retrieve path for pid: %d", pid);
        }
    }

    // this function can be called recursively by the kernel, for an interpreter
    // and a script/binary it is interpreting.
    if (bprm->recursion_depth == 0)
    {
        // Update the existing process on exec
        procp = process_tracking_update_process(
                    pid,
                    tid,
                    uid,
                    euid,
                    device,
                    inode,
                    path,
                    path_found,
                    to_windows_timestamp(&start_time),
                    CB_PROCESS_START_BY_EXEC,
                    task,
                    CB_EVENT_TYPE_PROCESS_START_EXEC,
                    REAL_START,
                    &context);
    } else
    {
        // This hook is called for the script first, with bprm->recursion_depth 0. If exec was called on a #! script
        // during the first call the path was the script, then on the next call, the interpreter is set as the path.
        // The interpreter can itself be a script so this hook can be called be called multiple times with
        // bprm->recursion_depth incremented on each call.

        if (path_found)
        {
            procp = process_tracking_get_process(pid, &context);
            if (procp)
            {
                // The previously set path is actually the script_path.
                // The script will report as an open event when the interpreter opens it.
                // The path from this call is the path of the interpreter.

                if (procp->shared_data->path)
                {
                    // The last path we are called with is the one we report so free any intermediate paths
                    cb_mem_cache_free_generic(procp->shared_data->path);
                }

                procp->shared_data->is_interpreter = true;
                procp->shared_data->path = cb_mem_cache_strdup(path, &context);

                // also need to update the file information
                procp->shared_data->exec_details.inode = inode;
                procp->shared_data->exec_details.device = device;

                procp->posix_details.inode = inode;
                procp->posix_details.device = device;
            }
        }
    }

    // Check to see if this should be banned or not.
    //   If it is banned, send the banned event and return an error
    //   If it is not banned, send a start event
    if (stat || killit)
    {
        if (killit)
        {
            process_tracking_mark_as_blocked(procp);
            event_send_block(procp,
                             BlockDuringProcessStartup,
                             TerminateFailureReasonNone,
                             0, // details
                             process_tracking_should_track_user() ? uid : (uid_t)-1,
                             path_buffer,
                             &context);
        }
        ret = -EPERM;
    }

CATCH_DEFAULT:
    process_tracking_put_process(procp, &context);
    put_path_buffer(path_buffer);
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

//
// Process start hook.  Callout called late in the exec process
//
void cb_bprm_committed_creds(struct linux_binprm *bprm)
{
    pid_t            pid     = getpid(current);
    uid_t            uid     = GET_UID();
    ProcessTracking *procp   = NULL;
    char *cmdline = NULL;

    DECLARE_ATOMIC_CONTEXT(context, pid);

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // If this process is not tracked, do not send an event
    // We have had issues scheduling from this hook.  (Though it should really be OK)
    procp = process_tracking_get_process(pid, &context);
    if (procp && !process_tracking_is_blocked(procp))
    {
        cmdline = get_path_buffer(&context);
        if (cmdline)
        {
            get_cmdline_from_binprm(bprm, cmdline, PATH_MAX);
        }

        process_tracking_set_cmdline(procp, cmdline, &context);

        event_send_start(procp,
                         process_tracking_should_track_user() ? uid : (uid_t)-1,
                         CB_PROCESS_START_BY_EXEC,
                         &context);
    }

CATCH_DEFAULT:
    process_tracking_put_process(procp, &context);
    put_path_buffer(cmdline);
    g_original_ops_ptr->bprm_committed_creds(bprm);
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
}
