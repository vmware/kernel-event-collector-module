// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "process-tracking-private.h"
#include "cb-test.h"
#include "priv.h"

bool is_process_tracked(pid_t pid, ProcessContext *context)
{
    bool ret = false;
    ProcessTracking *procp = process_tracking_get_process(pid, context);

    ret = (procp != NULL);

    process_tracking_put_process(procp, context);

    return ret;
}

void process_tracking_mark_as_blocked(ProcessTracking *procp)
{
    if (procp)
    {
        procp->exec_blocked = true;
    }
}

bool process_tracking_is_blocked(ProcessTracking *procp)
{
    return (procp && procp->exec_blocked);
}

pid_t process_tracking_exec_pid(ProcessTracking *procp)
{
    return procp ? procp->shared_data->exec_details.pid : 1;
}

void process_tracking_set_cmdline(ProcessTracking *procp, char *cmdline, ProcessContext *context)
{
    if (procp)
    {
        procp->shared_data->cmdline = cb_mem_cache_strdup(cmdline, context);
    }
}

SharedTrackingData *process_tracking_get_shared_data_ref(SharedTrackingData *shared_data, ProcessContext *context)
{
    TRY(shared_data);

    TRACE_IF_REF_DEBUGGING(DL_PROC_TRACKING, "    %s: %s %d shared_data Ref count: %ld/%ld (%p)",
        __func__,
        process_tracking_get_proc_name(shared_data->path),
        shared_data->exec_details.pid,
        atomic64_read(&shared_data->reference_count),
        atomic64_read(&shared_data->active_process_count),
        shared_data);

    atomic64_inc(&shared_data->reference_count);

CATCH_DEFAULT:
    return shared_data;
}

void process_tracking_set_shared_data(ProcessTracking *procp, SharedTrackingData *shared_data, ProcessContext *context)
{
    CANCEL_VOID(procp);

    // Make sure that we release the one we are holding
    process_tracking_release_shared_data_ref(procp->shared_data, context);

    // Set the new one, and take the reference
    procp->shared_data = process_tracking_get_shared_data_ref(shared_data, context);
}

void process_tracking_set_parent_shared_data(ProcessTracking *procp, SharedTrackingData *shared_data, ProcessContext *context)
{
    CANCEL_VOID(procp);

    TRACE_IF_REF_DEBUGGING(DL_PROC_TRACKING, "    %s parent_shared_data %p (old %p)",
        (shared_data ? "set" : "clear"),
        shared_data,
        procp->parent_shared_data);

    // Make sure that we release the one we are holding
    process_tracking_release_shared_data_ref(procp->parent_shared_data, context);

    // Set the new one, and take the reference
    procp->parent_shared_data = process_tracking_get_shared_data_ref(shared_data, context);
}

void process_tracking_set_event_info(ProcessTracking *procp, CB_EVENT_TYPE eventType, PCB_EVENT event, ProcessContext *context)
{
    TRY(procp && event);
    TRY(procp->shared_data);

    event->procInfo.all_process_details.array[FORK]             = procp->posix_details;
    event->procInfo.all_process_details.array[FORK_PARENT]      = procp->posix_parent_details;
    event->procInfo.all_process_details.array[FORK_GRANDPARENT] = procp->posix_grandparent_details;
    event->procInfo.all_process_details.array[EXEC]             = procp->shared_data->exec_details;
    event->procInfo.all_process_details.array[EXEC_PARENT]      = procp->shared_data->exec_parent_details;
    event->procInfo.all_process_details.array[EXEC_GRANDPARENT] = procp->shared_data->exec_grandparent_details;


    event->procInfo.path_found      = procp->shared_data->path_found;
    event->procInfo.path            = cb_mem_cache_get_generic(procp->shared_data->path, context);

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
        // Do nothing
        break;
    case CB_EVENT_TYPE_PROCESS_START_EXEC:
    case CB_EVENT_TYPE_PROCESS_BLOCKED:
        // For process start events we hold a reference to the parent process
        //  (This forces an exit of the parent to be sent after the start of a child)
        logger_set_process_data(event, procp->parent_shared_data, context);
        break;
    default:
        // For all other events we hold a reference to this process
        logger_set_process_data(event, procp->shared_data, context);
        break;
    }

CATCH_DEFAULT:
    // In some cases we expect this function to be called with a NULL event
    //  because we still need to free the parent shared data
    //  Example: This will happen if we are ignoring fork events.
    process_tracking_set_parent_shared_data(procp, NULL, context);
}

char *process_tracking_get_path(SharedTrackingData *shared_data)
{
    return shared_data->path ? shared_data->path : "<unknown>";
}

void process_tracking_store_exit_event(ProcessTracking *procp, PCB_EVENT event, ProcessContext *context)
{
    PCB_EVENT prev_event;

    CANCEL_VOID(procp);

    // This is the last exit, so store the event in the tracking entry to be sent later
    prev_event = (PCB_EVENT) atomic64_xchg(&procp->shared_data->exit_event, (uint64_t) event);

    // This should never happen, but just in case
    logger_free_event(prev_event, context);
}

static int __hashtbl_search_callback(HashTbl * hashTblp, HashTableNode * nodep, void *priv, ProcessContext *context);

void is_process_tracked_get_state_by_inode(RUNNING_BANNED_INODE_S *psRunningInodesToBan, ProcessContext *context)
{
    hashtbl_read_for_each_generic(g_process_tracking_data.table, __hashtbl_search_callback, psRunningInodesToBan, context);

    return;
}

bool process_tracking_has_active_process(ProcessTracking *procp)
{
    return procp != NULL && atomic64_read(&procp->shared_data->active_process_count) != 0;
}

// Note: This function is used as a callback by hashtbl_read_for_each_generic called from
//       is_process_tracked_get_state_by_inode also note that it is called from inside a spinlock.
//       Therefore, in the future if modifications are required be aware that any function call that may
//       sleep should be avoided.
//       We also allocate an array of pointers and it is the responsibility of the caller to free them when done.
static int __hashtbl_search_callback(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context)
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
        temp = (RUNNING_PROCESSES_TO_BAN *)cb_mem_cache_alloc_generic(sizeof(RUNNING_PROCESSES_TO_BAN), context);
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

void process_tracking_update_op_cnts(ProcessTracking *procp, CB_EVENT_TYPE event_type, int action)
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
