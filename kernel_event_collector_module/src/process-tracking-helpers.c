// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "process-tracking-private.h"
#include "cb-spinlock.h"
#include "cb-test.h"
#include "priv.h"
#include "mem-alloc.h"
#include "event-factory.h"

PathData *__ec_process_tracking_get_path_data(ExecIdentity * exec_identity, ProcessContext *context);

bool ec_is_process_tracked(pid_t pid, ProcessContext *context)
{
    bool ret = false;
    ProcessHandle *process_handle = ec_process_tracking_get_handle(pid, context);

    ret = (process_handle != NULL);

    ec_process_tracking_put_handle(process_handle, context);

    return ret;
}

void ec_process_tracking_mark_as_blocked(ProcessHandle *process_handle)
{
    if (process_handle)
    {
        ec_process_posix_identity(process_handle)->exec_blocked = true;
    }
}

bool ec_process_tracking_is_blocked(ProcessHandle *process_handle)
{
    return (process_handle && ec_process_posix_identity(process_handle)->exec_blocked);
}

pid_t ec_process_tracking_exec_pid(ProcessHandle *process_handle, ProcessContext *context)
{
    pid_t result = 1;

    TRY(process_handle);

    result = ec_process_exec_identity(process_handle)->exec_details.pid;

CATCH_DEFAULT:
    return result;
}

void ec_process_tracking_set_cmdline(ExecHandle *exec_handle, char *cmdline, ProcessContext *context)
{
    if (exec_handle)
    {
        ExecIdentity *exec_identity = ec_exec_identity(exec_handle);

        ec_write_lock(&exec_identity->string_lock, context);
        ec_mem_put(exec_identity->cmdline);
        exec_identity->cmdline = ec_mem_get(cmdline, context);
        ec_write_unlock(&exec_identity->string_lock, context);

        // No need to be locked while doing this
        ec_mem_put(exec_handle->cmdline);
        exec_handle->cmdline = ec_mem_get(cmdline, context);
    }
}

char *ec_process_tracking_get_cmdline(ExecIdentity *exec_identity, ProcessContext *context)
{
    char *cmdline = NULL;

    if (exec_identity)
    {
        if (!exec_identity->is_complete)
        {
            ec_read_lock(&exec_identity->string_lock, context);
        }
        cmdline = ec_mem_get(exec_identity->cmdline, context);
        if (!exec_identity->is_complete)
        {
            ec_read_unlock(&exec_identity->string_lock, context);
        }
    }
    return cmdline;
}

void ec_process_tracking_set_proc_cmdline(ProcessHandle *process_handle, char *cmdline, ProcessContext *context)
{
    CANCEL_VOID(process_handle && cmdline);

    // Duplicate the command line for storage
    cmdline = ec_mem_strdup(cmdline, context);

    ec_process_tracking_set_cmdline(ec_process_exec_handle(process_handle), cmdline, context);

    ec_mem_put(cmdline);
}

ExecIdentity *ec_process_tracking_get_exec_identity_ref(ExecIdentity *exec_identity, ProcessContext *context)
{
    TRY(exec_identity);

    ec_mem_cache_get(exec_identity, context);

    if (g_process_tracking_ref_debug)
    {
        __ec_process_tracking_print_ref(DL_PROC_TRACKING, __func__, exec_identity, context);
    }

CATCH_DEFAULT:
    return exec_identity;
}

void ec_process_tracking_put_exec_identity(ExecIdentity *exec_identity, ProcessContext *context)
{
    CANCEL_VOID(exec_identity);

    if (g_process_tracking_ref_debug)
    {
        __ec_process_tracking_print_ref(DL_PROC_TRACKING, __func__, exec_identity, context);
    }

    ec_mem_cache_put(exec_identity, context);
}

ExecIdentity *ec_process_tracking_get_exec_identity(PosixIdentity *posix_identity, ProcessContext *context)
{
    ExecIdentity *exec_identity = NULL;

    if (posix_identity)
    {
        // This should be called while holding the bucket lock
        exec_identity = ec_process_tracking_get_exec_identity_ref(posix_identity->exec_identity, context);
    }

    return exec_identity;
}

void ec_process_posix_identity_set_exec_identity(PosixIdentity *posix_identity, ExecIdentity *exec_identity, ProcessContext *context)
{
    CANCEL_VOID(posix_identity);

    // Note: This function may be called while holding the hash-table bucket lock.
    //  1. During the update call we explicitly lock the bucket
    //  2. During the create call we do not lock because the posix entry is not inserted
    //  3. During the delete call we do not lock because it is the last reference

    // Make sure that we release the one we are holding
    ec_process_tracking_put_exec_identity(posix_identity->exec_identity, context);

    // Set the new one, and take the reference
    posix_identity->exec_identity = ec_process_tracking_get_exec_identity_ref(exec_identity, context);
}

void ec_process_tracking_set_exec_identity(ProcessHandle *process_handle, ExecIdentity *exec_identity, ProcessContext *context)
{
    if (process_handle && exec_identity)
    {
        // We need to lock the hash table to change the data here
        ec_hashtbl_write_lock(&g_process_tracking_data.table, &ec_process_posix_identity(process_handle)->pt_key, context);
        ec_process_posix_identity_set_exec_identity(ec_process_posix_identity(process_handle), exec_identity, context);
        ec_hashtbl_write_unlock(&g_process_tracking_data.table, &ec_process_posix_identity(process_handle)->pt_key, context);

        // Updating the handle does not need to be done while locked
        ec_process_exec_handle_set_exec_identity(&process_handle->exec_handle, exec_identity, context);
    }
}

void ec_process_tracking_disown_exec_identity(ProcessHandle *process_handle, ProcessContext *context)
{
    ExecIdentity *exec_identity = ec_process_exec_identity(process_handle);

    CANCEL_VOID(exec_identity);

    // Safely set posix_identity's exec_identity to NULL before we, potentially, free it
    ec_process_tracking_set_exec_identity(process_handle, NULL, context);

    // We want to disown the exec_identity. This will ensure it is deleted when the last reference count is dropped.
    ec_mem_cache_disown(exec_identity, context);
}

ProcessHandle *ec_process_handle_alloc(PosixIdentity *posix_identity, ProcessContext *context)
{
    ProcessHandle *process_handle = ec_mem_alloc(
        sizeof(ProcessHandle),
        context);

    if (process_handle)
    {
        // This takes ownership of the reference provided by the hash table
        process_handle->posix_identity = posix_identity;
        memset(&process_handle->exec_handle, 0, sizeof(process_handle->exec_handle));
        ec_process_exec_handle_set_exec_identity(&process_handle->exec_handle, posix_identity->exec_identity, context);

        // Path and cmdline are allowed to be NULL, and should be tested accordingly
        TRY(process_handle->exec_handle.identity);
    }
    return process_handle;

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, context);
    return NULL;
}

void ec_process_tracking_put_handle(ProcessHandle *process_handle, ProcessContext *context)
{
    if (process_handle)
    {
        ec_process_tracking_put_exec_handle(&process_handle->exec_handle, context);
        ec_hashtbl_put(&g_process_tracking_data.table, process_handle->posix_identity, context);
        ec_mem_free(process_handle);
    }
}

void ec_process_tracking_put_exec_handle(ExecHandle *exec_handle, ProcessContext *context)
{
    if (exec_handle)
    {
        ec_path_cache_put(exec_handle->path_data, context);
        ec_mem_put(exec_handle->cmdline);
        ec_process_tracking_put_exec_identity(exec_handle->identity, context);

        memset(exec_handle, 0, sizeof(ExecHandle));
    }
}

void ec_process_exec_handle_clone(ExecHandle *from, ExecHandle *to, ProcessContext *context)
{
    ec_process_tracking_put_exec_handle(to, context);

    if (from)
    {
        // Note: I do not want to call ec_process_exec_handle_set_exec_identity here because I want to clone the current
        //  handle and not get pointers from from->identity
        to->identity = ec_process_tracking_get_exec_identity_ref(from->identity, context);
        to->path_data = ec_path_cache_get(from->path_data, context);
        to->cmdline = ec_mem_get(from->cmdline, context);
    }
}

void ec_process_exec_handle_set_exec_identity(ExecHandle *exec_handle, ExecIdentity *exec_identity, ProcessContext *context)
{
    if (exec_handle)
    {
        ec_process_tracking_put_exec_handle(exec_handle, context);

        exec_handle->identity = ec_process_tracking_get_exec_identity_ref(exec_identity, context);
        exec_handle->path_data = __ec_process_tracking_get_path_data(exec_identity, context);
        exec_handle->cmdline = ec_process_tracking_get_cmdline(exec_identity, context);
    }
}

ExecHandle *ec_process_tracking_get_temp_exec_handle(ProcessHandle *process_handle, ProcessContext *context)
{
    return process_handle ? &ec_process_posix_identity(process_handle)->temp_exec_handle : NULL;
}

void ec_process_tracking_set_temp_exec_handle(ProcessHandle *process_handle, ExecHandle *exec_handle, ProcessContext *context)
{
    CANCEL_VOID(process_handle);

    ec_hashtbl_write_lock(&g_process_tracking_data.table, &ec_process_posix_identity(process_handle)->pt_key, context);
    // This call dereferences the existing temp_exec_handle and replaces it. We need to atomically dref the old handle's
    // elements and replace them, otherwise the exec_identity and it's parts can be dereferenced more than once.
    ec_process_exec_handle_clone(exec_handle, &ec_process_posix_identity(process_handle)->temp_exec_handle, context);
    ec_hashtbl_write_unlock(&g_process_tracking_data.table, &ec_process_posix_identity(process_handle)->pt_key, context);
}

void ec_process_tracking_set_event_info(ProcessHandle *process_handle, CB_EVENT_TYPE eventType, PCB_EVENT event, ProcessContext *context)
{
    PathData *path_data;

    TRY(process_handle && event);

    event->procInfo.all_process_details.array[FORK]             = ec_process_posix_identity(process_handle)->posix_details;
    event->procInfo.all_process_details.array[FORK_PARENT]      = ec_process_posix_identity(process_handle)->posix_parent_details;
    event->procInfo.all_process_details.array[FORK_GRANDPARENT] = ec_process_posix_identity(process_handle)->posix_grandparent_details;
    event->procInfo.all_process_details.array[EXEC]             = ec_process_exec_identity(process_handle)->exec_details;
    event->procInfo.all_process_details.array[EXEC_PARENT]      = ec_process_exec_identity(process_handle)->exec_parent_details;
    event->procInfo.all_process_details.array[EXEC_GRANDPARENT] = ec_process_exec_identity(process_handle)->exec_grandparent_details;

    path_data = ec_process_path_data(process_handle);

    if (path_data)
    {
        event->procInfo.path_found = path_data->path_found;
        event->procInfo.path       = ec_mem_get(path_data->path, context);// hold reference
        event->procInfo.path_size  = ec_mem_size(event->procInfo.path);
    } else
    {
        event->procInfo.path_found = false;
    }

CATCH_DEFAULT:
    // In some cases we expect this function to be called with a NULL event
    //  because we still need to free the parent shared data
    //  Example: This will happen if we are ignoring fork events.
    ec_process_tracking_set_temp_exec_handle(process_handle, NULL, context);
}

char *ec_process_tracking_get_path(ExecIdentity *exec_identity, ProcessContext *context)
{
    char *path = NULL;

    if (exec_identity)
    {
        if (!exec_identity->is_complete)
        {
            ec_read_lock(&exec_identity->string_lock, context);
        }
        if (exec_identity->path_data)
        {
            path = ec_mem_get(exec_identity->path_data->path, context);
        }
        if (!exec_identity->is_complete)
        {
            ec_read_unlock(&exec_identity->string_lock, context);
        }
    }

    return path;
}

PathData *__ec_process_tracking_get_path_data(ExecIdentity *exec_identity, ProcessContext *context)
{
    PathData *path_data = NULL;

    if (exec_identity)
    {
        if (!exec_identity->is_complete)
        {
            ec_read_lock(&exec_identity->string_lock, context);
        }
        path_data = ec_path_cache_get(exec_identity->path_data, context);
        if (!exec_identity->is_complete)
        {
            ec_read_unlock(&exec_identity->string_lock, context);
        }
    }

    return path_data;
}

void ec_process_tracking_set_path(ProcessHandle *process_handle, PathData *path_data, ProcessContext *context)
{
     if (process_handle)
     {
         ec_write_lock(&ec_process_exec_identity(process_handle)->string_lock, context);
         ec_path_cache_put(ec_process_exec_identity(process_handle)->path_data, context);
         ec_process_exec_identity(process_handle)->path_data = ec_path_cache_get(path_data, context);
         ec_write_unlock(&ec_process_exec_identity(process_handle)->string_lock, context);

         // We do not need to be locked to update the handle
         ec_path_cache_put(ec_process_exec_handle(process_handle)->path_data, context);
         ec_process_exec_handle(process_handle)->path_data = ec_path_cache_get(path_data, context);
     }
}

void ec_process_tracking_put_path(char *path, ProcessContext *context)
{
    ec_mem_put(path);
}

int __ec_hashtbl_search_callback(HashTbl * hashTblp, void *datap, void *priv, ProcessContext *context);

void ec_is_process_tracked_get_state_by_inode(RUNNING_BANNED_INODE_S *psRunningInodesToBan, ProcessContext *context)
{
    ec_hashtbl_read_for_each(&g_process_tracking_data.table, __ec_hashtbl_search_callback, psRunningInodesToBan, context);

    return;
}

bool ec_process_tracking_has_active_process(PosixIdentity *posix_identity, ProcessContext *context)
{
    bool result = false;
    ExecIdentity *exec_identity = ec_process_tracking_get_exec_identity(posix_identity, context);

    TRY(posix_identity && exec_identity);

    result = atomic64_read(&exec_identity->active_process_count) != 0;

CATCH_DEFAULT:
    ec_process_tracking_put_exec_identity(exec_identity, context);
    return result;
}

// Note: This function is used as a callback by ec_hashtbl_read_for_each called from
//       ec_is_process_tracked_get_state_by_inode also note that it is called from inside a spinlock.
//       Therefore, in the future if modifications are required be aware that any function call that may
//       sleep should be avoided.
//       We also allocate an array of pointers and it is the responsibility of the caller to free them when done.
int __ec_hashtbl_search_callback(HashTbl *hashTblp, void *datap, void *priv, ProcessContext *context)
{
    PosixIdentity *posix_identity = (PosixIdentity *)datap;
    RUNNING_BANNED_INODE_S *psRunningInodesToBan = NULL;
    RUNNING_PROCESSES_TO_BAN *temp = NULL;

    TRY(posix_identity);

    // Saftey first
    // TRY_DO(priv,
    // {
    //     TRACE( DL_ERROR, "%s:%d NULL ptr provided as function argument [%p=posix_data %p=priv]. Bailing...",
    //                      __func__, __LINE__, posix_data, priv);
    // });

    psRunningInodesToBan = (RUNNING_BANNED_INODE_S *)priv;

    //Did we match based on inode?
    if (posix_identity->posix_details.device == psRunningInodesToBan->device &&
        posix_identity->posix_details.inode == psRunningInodesToBan->inode)
    {
        //Allocate a new list element for banning to hold this process pointer
        temp = (RUNNING_PROCESSES_TO_BAN *)ec_mem_alloc(sizeof(RUNNING_PROCESSES_TO_BAN), context);
        TRY_DO(temp,
        {
            TRACE(DL_ERROR, "%s:%d Out of memory!\n", __func__, __LINE__);
        });

        //Update our structure
        temp->process_handle = ec_hashtbl_get(hashTblp, posix_identity, context);
        list_add(&(temp->list), &(psRunningInodesToBan->BanList.list));
        psRunningInodesToBan->count++;
    }
CATCH_DEFAULT:
    return ACTION_CONTINUE;
}

void ec_process_tracking_update_op_cnts(PosixIdentity *posix_identity, CB_EVENT_TYPE event_type, int action)
{
    switch (event_type)
    {
    case CB_EVENT_TYPE_PROCESS_START:
        posix_identity->process_op_cnt += 1;
        posix_identity->process_create += 1;
        if (action == CB_PROCESS_START_BY_FORK)
        {
            g_process_tracking_data.create_by_fork += 1;
        } else if (action == CB_PROCESS_START_BY_EXEC)
        {
            g_process_tracking_data.create_by_exec += 1;
        }
        break;

    case CB_EVENT_TYPE_PROCESS_EXIT:
    case CB_EVENT_TYPE_PROCESS_LAST_EXIT:
        posix_identity->process_op_cnt += 1;
        posix_identity->process_exit += 1;
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
        posix_identity->file_op_cnt += 1;
        posix_identity->file_map_exec += 1;
        break;

    case CB_EVENT_TYPE_FILE_CREATE:
        posix_identity->file_op_cnt += 1;
        posix_identity->file_create += 1;
        break;

    case CB_EVENT_TYPE_FILE_DELETE:
        posix_identity->file_op_cnt += 1;
        posix_identity->file_delete += 1;
        break;

    case CB_EVENT_TYPE_FILE_WRITE:
        posix_identity->file_op_cnt += 1;
        if (posix_identity->file_write == 0)
        {
            posix_identity->file_open += 1;
        }
        posix_identity->file_write += 1;

    case CB_EVENT_TYPE_FILE_CLOSE:
        posix_identity->file_op_cnt += 1;
        posix_identity->file_close += 1;
        break;

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
        posix_identity->net_op_cnt += 1;
        posix_identity->net_connect += 1;
        break;

    case CB_EVENT_TYPE_NET_CONNECT_POST:
        posix_identity->net_op_cnt  += 1;
        posix_identity->net_connect += 1;
        break;

    case CB_EVENT_TYPE_NET_ACCEPT:
        posix_identity->net_op_cnt += 1;
        posix_identity->net_accept += 1;
        break;

    case CB_EVENT_TYPE_DNS_RESPONSE:
        posix_identity->net_op_cnt += 1;
        posix_identity->net_dns += 1;
        break;

    default:
        break;
    }
}

PosixIdentity *ec_process_posix_identity(ProcessHandle *process_handle)
{
    return process_handle ? process_handle->posix_identity : NULL;
}

ExecIdentity *ec_process_exec_identity(ProcessHandle *process_handle)
{
    return process_handle ? process_handle->exec_handle.identity : NULL;
}

ExecHandle *ec_process_exec_handle(ProcessHandle *process_handle)
{
    return process_handle ? &process_handle->exec_handle : NULL;
}

char *ec_process_path(ProcessHandle *process_handle)
{
    return process_handle ? ec_exec_path(&process_handle->exec_handle) : NULL;
}

PathData *ec_process_path_data(ProcessHandle *process_handle)
{
    return process_handle ? ec_exec_path_data(&process_handle->exec_handle) : NULL;
}

char *ec_process_cmdline(ProcessHandle *process_handle)
{
    return process_handle ? process_handle->exec_handle.cmdline : NULL;
}

ExecIdentity *ec_exec_identity(ExecHandle *exec_handle)
{
    return exec_handle ? exec_handle->identity : NULL;
}

char *ec_exec_path(ExecHandle *exec_handle)
{
    return (exec_handle && exec_handle->path_data) ? exec_handle->path_data->path : NULL;
}

PathData *ec_exec_path_data(ExecHandle *exec_handle)
{
    return exec_handle ? exec_handle->path_data : NULL;
}

void __ec_process_tracking_print_ref(int log_level, const char *calling_func, ExecIdentity *exec_identity, ProcessContext *context)
{
    char *path = NULL;

    CANCEL_VOID(exec_identity);
    CANCEL_VOID(MAY_TRACE_LEVEL(log_level));

    path = ec_process_tracking_get_path(exec_identity, context);

    TRACE(log_level, "    %s: %s %d exec_identity (%s) (ref/active: %lld/%lld) (%p)",
          calling_func,
          ec_process_tracking_get_proc_name(path),
          exec_identity->exec_details.pid,
          ec_mem_cache_is_owned(exec_identity, context) ? "owned" : "not owned",
          ec_mem_cache_ref_count(exec_identity, context),
          (long long) atomic64_read(&exec_identity->active_process_count),
          exec_identity);
    ec_process_tracking_put_path(path, context);
}
