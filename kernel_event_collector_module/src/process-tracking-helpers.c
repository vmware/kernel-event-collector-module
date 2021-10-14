// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "process-tracking-private.h"
#include "cb-test.h"
#include "priv.h"

bool ec_is_process_tracked(pid_t pid, ProcessContext *context)
{
    bool ret = false;
    ProcessTracking *procp = ec_process_tracking_get_process(pid, context);

    ret = (procp != NULL);

    ec_process_tracking_put_process(procp, context);

    return ret;
}

void ec_process_tracking_mark_as_blocked(ProcessTracking *procp)
{
    if (procp)
    {
        procp->exec_blocked = true;
    }
}

bool ec_process_tracking_is_blocked(ProcessTracking *procp)
{
    return (procp && procp->exec_blocked);
}

pid_t ec_process_tracking_exec_pid(ProcessTracking *procp, ProcessContext *context)
{
    pid_t result = 1;
    SharedTrackingData *shared_data = ec_process_tracking_get_shared_data(procp, context);

    TRY(procp && shared_data);

    result = shared_data->exec_details.pid;

CATCH_DEFAULT:
    ec_process_tracking_put_shared_data(shared_data, context);
    return result;
}

void ec_process_tracking_set_cmdline(SharedTrackingData *shared_data, char *cmdline, ProcessContext *context)
{
    if (shared_data)
    {
        // TODO: Add lock
        ec_process_tracking_put_cmdline(shared_data->cmdline, context);
        shared_data->cmdline = (cmdline ? ec_mem_cache_get_generic(cmdline, context) : NULL);
    }
}

char *ec_process_tracking_get_cmdline(SharedTrackingData *shared_data, ProcessContext *context)
{
    char *cmdline = NULL;

    if (shared_data)
    {
        // TODO: Add lock here

        cmdline = ec_mem_cache_get_generic(shared_data->cmdline, context);
    }
    return cmdline;
}

void ec_process_tracking_put_cmdline(char *cmdline, ProcessContext *context)
{
    ec_mem_cache_put_generic(cmdline);
}

void ec_process_tracking_set_proc_cmdline(ProcessTracking *procp, char *cmdline, ProcessContext *context)
{
    SharedTrackingData *shared_data = ec_process_tracking_get_shared_data(procp, context);

    TRY(shared_data && cmdline);

    // Duplicate the command line for storage
    cmdline = ec_mem_cache_strdup(cmdline, context);

    ec_process_tracking_set_cmdline(shared_data, cmdline, context);

    ec_mem_cache_put_generic(cmdline);

CATCH_DEFAULT:
    ec_process_tracking_put_shared_data(shared_data, context);
}

SharedTrackingData *ec_process_tracking_get_shared_data_ref(SharedTrackingData *shared_data, ProcessContext *context)
{
    TRY(shared_data);

    #ifdef _REF_DEBUGGING
    if (MAY_TRACE_LEVEL(DL_PROC_TRACKING))
    {
        char *path = ec_process_tracking_get_path(shared_data, context);

        TRACE(DL_PROC_TRACKING, "    %s: %s %d shared_data Ref count: %ld/%ld (%p)",
            __func__,
            ec_process_tracking_get_proc_name(path),
            shared_data->exec_details.pid,
            atomic64_read(&shared_data->reference_count),
            atomic64_read(&shared_data->active_process_count),
            shared_data);
        ec_process_tracking_put_path(path, context);
    }
    #endif

    atomic64_inc(&shared_data->reference_count);

CATCH_DEFAULT:
    return shared_data;
}

SharedTrackingData *ec_process_tracking_get_shared_data(ProcessTracking *procp, ProcessContext *context)
{
    SharedTrackingData *shared_data = NULL;

    if (procp)
    {
        // TODO: Add lock here

        shared_data = ec_process_tracking_get_shared_data_ref(procp->shared_data, context);
    }

    return shared_data;
}

void ec_process_tracking_set_shared_data(ProcessTracking *procp, SharedTrackingData *shared_data, ProcessContext *context)
{
    CANCEL_VOID(procp);

    // TODO: Add lock here

    // Make sure that we release the one we are holding
    ec_process_tracking_put_shared_data(procp->shared_data, context);

    // Set the new one, and take the reference
    procp->shared_data = ec_process_tracking_get_shared_data_ref(shared_data, context);
}

SharedTrackingData *ec_process_tracking_get_temp_shared_data(ProcessTracking *procp, ProcessContext *context)
{
    SharedTrackingData *shared_data = NULL;

    TRY(procp);

    // TODO: Add lock here

    shared_data = ec_process_tracking_get_shared_data_ref(procp->temp_shared_data, context);

CATCH_DEFAULT:
    return shared_data;
}

void ec_process_tracking_set_temp_shared_data(ProcessTracking *procp, SharedTrackingData *shared_data, ProcessContext *context)
{
    CANCEL_VOID(procp);

    // TODO: Add lock here

    TRACE_IF_REF_DEBUGGING(DL_PROC_TRACKING, "    %s parent_shared_data %p (old %p)",
        (shared_data ? "set" : "clear"),
        shared_data,
        procp->temp_shared_data);

    // Make sure that we release the one we are holding
    ec_process_tracking_put_shared_data(procp->temp_shared_data, context);

    // Set the new one, and take the reference
    procp->temp_shared_data = ec_process_tracking_get_shared_data_ref(shared_data, context);
}

void ec_process_tracking_set_event_info(ProcessTracking *procp, CB_INTENT_TYPE intentType, CB_EVENT_TYPE eventType, PCB_EVENT event, ProcessContext *context)
{
    SharedTrackingData *shared_data = ec_process_tracking_get_shared_data(procp, context);
    SharedTrackingData *temp_shared_data = NULL;

    TRY(procp && event && shared_data);

    event->procInfo.all_process_details.array[FORK]             = procp->posix_details;
    event->procInfo.all_process_details.array[FORK_PARENT]      = procp->posix_parent_details;
    event->procInfo.all_process_details.array[FORK_GRANDPARENT] = procp->posix_grandparent_details;
    event->procInfo.all_process_details.array[EXEC]             = shared_data->exec_details;
    event->procInfo.all_process_details.array[EXEC_PARENT]      = shared_data->exec_parent_details;
    event->procInfo.all_process_details.array[EXEC_GRANDPARENT] = shared_data->exec_grandparent_details;


    event->procInfo.path_found      = shared_data->path_found;
    event->procInfo.path            = ec_process_tracking_get_path(shared_data, context);// hold reference
    if (event->procInfo.path)
    {
        event->procInfo.path_size    = strlen(event->procInfo.path) + 1;
    }

    // We need to ensure that user-space does not get any exit events for a
    //  process until all events for that process are already collected.
    //  This can be tricky because exit events belong in the P0 queue so they
    //  are not dropped.  But other events will be in the P1 and P2 queues.
    // To solve this, each event will hold a reference to the shared_data object
    //  for its associated process.  When an exit is observed, the exit event
    //  is stored in the shared_data.  When an event is deleted, the reference
    //  will be released (either sent to user-space or dropped).
    // When the shared_data reference_count reaches 0, the event will be placed
    //  in the queue.
    switch (eventType)
    {
    case CB_EVENT_TYPE_PROCESS_EXIT:
    case CB_EVENT_TYPE_PROCESS_LAST_EXIT:
    case CB_EVENT_TYPE_PROCESS_START_EXEC:
    case CB_EVENT_TYPE_PROCESS_BLOCKED:
        // For process start events we hold a reference to the parent process
        //  (This forces an exit of the parent to be sent after the start of a child)
        // For process exit events we hold a reference to the child preocess
        //  (This forces the child's exit to be sent after the parent's exit)


        temp_shared_data = ec_process_tracking_get_temp_shared_data(procp, context);
        ec_event_set_process_data(event, temp_shared_data, context);
        break;
    default:
        // For all other events we hold a reference to this process
        ec_event_set_process_data(event, shared_data, context);
        break;
    }

    event->intentType = intentType;

CATCH_DEFAULT:
    // In some cases we expect this function to be called with a NULL event
    //  because we still need to free the parent shared data
    //  Example: This will happen if we are ignoring fork events.
    ec_process_tracking_set_temp_shared_data(procp, NULL, context);
    ec_process_tracking_put_shared_data(shared_data, context);
    ec_process_tracking_put_shared_data(temp_shared_data, context);
}

char *ec_process_tracking_get_path(SharedTrackingData *shared_data, ProcessContext *context)
{
    char *path = NULL;

    if (shared_data)
    {
        // TODO: Add lock
        path = ec_mem_cache_get_generic(shared_data->path, context);
    }

    return path;
}

void ec_process_tracking_set_path(SharedTrackingData *shared_data, char *path, ProcessContext *context)
{
     if (shared_data)
     {
         // TODO: Add lock
         ec_process_tracking_put_path(shared_data->path, context);
         shared_data->path = (path ? ec_mem_cache_get_generic(path, context) : NULL);
     }
}

void ec_process_tracking_put_path(char *path, ProcessContext *context)
{
    ec_mem_cache_put_generic(path);
}

void ec_process_tracking_store_exit_event(ProcessTracking *procp, PCB_EVENT event, ProcessContext *context)
{
    PCB_EVENT prev_event;
    SharedTrackingData *shared_data = ec_process_tracking_get_shared_data(procp, context);

    CANCEL_VOID(procp && shared_data);

    // This is the last exit, so store the event in the tracking entry to be sent later
    prev_event = (PCB_EVENT) atomic64_xchg(&shared_data->exit_event, (uint64_t) event);

    // This should never happen, but just in case
    ec_free_event(prev_event, context);

    ec_process_tracking_put_shared_data(shared_data, context);
}

int __ec_hashtbl_search_callback(HashTbl * hashTblp, HashTableNode * nodep, void *priv, ProcessContext *context);

void ec_is_process_tracked_get_state_by_inode(RUNNING_BANNED_INODE_S *psRunningInodesToBan, ProcessContext *context)
{
    ec_hashtbl_read_for_each_generic(g_process_tracking_data.table, __ec_hashtbl_search_callback, psRunningInodesToBan, context);

    return;
}

bool ec_process_tracking_has_active_process(ProcessTracking *procp, ProcessContext *context)
{
    bool result = false;
    SharedTrackingData *shared_data = ec_process_tracking_get_shared_data(procp, context);

    TRY(procp && shared_data);

    result = atomic64_read(&shared_data->active_process_count) != 0;

CATCH_DEFAULT:
    ec_process_tracking_put_shared_data(shared_data, context);
    return result;
}

// Note: This function is used as a callback by ec_hashtbl_read_for_each_generic called from
//       ec_is_process_tracked_get_state_by_inode also note that it is called from inside a spinlock.
//       Therefore, in the future if modifications are required be aware that any function call that may
//       sleep should be avoided.
//       We also allocate an array of pointers and it is the responsibility of the caller to free them when done.
int __ec_hashtbl_search_callback(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context)
{
    ProcessTracking *procp = NULL;
    RUNNING_BANNED_INODE_S *psRunningInodesToBan = NULL;
    RUNNING_PROCESSES_TO_BAN *temp = NULL;

    TRY(nodep);

    // Saftey first
    // TRY_DO(priv,
    // {
    //     TRACE( DL_ERROR, "%s:%d NULL ptr provided as function argument [%p=nodep %p=priv]. Bailing...",
    //                      __func__, __LINE__, nodep, priv);
    // });

    procp = (ProcessTracking *)nodep;
    psRunningInodesToBan = (RUNNING_BANNED_INODE_S *)priv;

    //Did we match based on inode?
    if (procp->posix_details.device == psRunningInodesToBan->device &&
        procp->posix_details.inode == psRunningInodesToBan->inode)
    {
        //Allocate a new list element for banning to hold this process pointer
        temp = (RUNNING_PROCESSES_TO_BAN *)ec_mem_cache_alloc_generic(sizeof(RUNNING_PROCESSES_TO_BAN), context);
        TRY_DO(temp,
        {
            TRACE(DL_ERROR, "%s:%d Out of memory!\n", __func__, __LINE__);
        });

        //Update our structure
        temp->procp = procp;
        list_add(&(temp->list), &(psRunningInodesToBan->BanList.list));
        psRunningInodesToBan->count++;
    }
CATCH_DEFAULT:
    return ACTION_CONTINUE;
}

void ec_process_tracking_update_op_cnts(ProcessTracking *procp, CB_EVENT_TYPE event_type, int action)
{
    switch (event_type)
    {
    case CB_EVENT_TYPE_PROCESS_START:
        procp->process_op_cnt += 1;
        procp->process_create += 1;
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
        procp->process_op_cnt += 1;
        procp->process_exit += 1;
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
        procp->file_op_cnt += 1;
        procp->file_map_exec += 1;
        break;

    case CB_EVENT_TYPE_FILE_CREATE:
        procp->file_op_cnt += 1;
        procp->file_create += 1;
        break;

    case CB_EVENT_TYPE_FILE_DELETE:
        procp->file_op_cnt += 1;
        procp->file_delete += 1;
        break;

    case CB_EVENT_TYPE_FILE_WRITE:
        procp->file_op_cnt += 1;
        if (procp->file_write == 0)
        {
            procp->file_open += 1;
        }
        procp->file_write += 1;

    case CB_EVENT_TYPE_FILE_CLOSE:
        procp->file_op_cnt += 1;
        procp->file_close += 1;
        break;

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
        procp->net_op_cnt += 1;
        procp->net_connect += 1;
        break;

    case CB_EVENT_TYPE_NET_CONNECT_POST:
        procp->net_op_cnt  += 1;
        procp->net_connect += 1;
        break;

    case CB_EVENT_TYPE_NET_ACCEPT:
        procp->net_op_cnt += 1;
        procp->net_accept += 1;
        break;

    case CB_EVENT_TYPE_DNS_RESPONSE:
        procp->net_op_cnt += 1;
        procp->net_dns += 1;
        break;

    default:
        break;
    }
}
