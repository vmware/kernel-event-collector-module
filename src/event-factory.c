// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "event-factory.h"
#include "net-helper.h"
#include "file-types.h"
#include "priv.h"

static const char *StartAction_ToString(int start_action)
{
    switch (start_action)
    {
        case CB_PROCESS_START_BY_FORK: return "FORK"; break;
        case CB_PROCESS_START_BY_EXEC: return "EXEC"; break;
        case CB_PROCESS_START_BY_DISCOVER: return "DISCOVER"; break;

        default:
            break;
    }
    return "??";
}

PCB_EVENT factory_alloc_event(ProcessTracking *procp,
                                     CB_EVENT_TYPE   eventType,
                                     int             trace_level,
                                     const char *type_msg,
                                     const char *status_msg,
                                     ProcessContext *context)
{
    PCB_EVENT event = NULL;

    if (procp && type_msg)
    {
        TRACE(trace_level, "%s%s %s of %d by %d (reported as %d by %d)",
               type_msg,
               (status_msg ? status_msg : ""),
               (procp->shared_data->path ? procp->shared_data->path : "<unknown>"),
               procp->posix_details.pid,
               procp->posix_parent_details.pid,
               procp->shared_data->exec_details.pid,
               procp->shared_data->exec_parent_details.pid);
    }

    // This will return a NULL event if we are configured to not send this event type
    event = logger_alloc_event(eventType, context);

    // We still call this even for a NULL event to give the process_tracking a chance
    //  to clean up any private data
    process_tracking_set_event_info(procp, eventType, event, context);

    return event;
}

void event_send_start(ProcessTracking *procp,
                      uid_t            uid,
                      int              start_action,
                      ProcessContext *context)
{
    PCB_EVENT event = NULL;

    CANCEL_VOID(procp);

    event = factory_alloc_event(
        procp,
        start_action != CB_PROCESS_START_BY_FORK ? CB_EVENT_TYPE_PROCESS_START_EXEC : CB_EVENT_TYPE_PROCESS_START_FORK,
        DL_PROCESS,
        StartAction_ToString(start_action),
        (procp && procp->is_real_start ? "" : " <FAKE>"),
        context);

    CANCEL_VOID(event);

    // Populate the event
    event->processStart.uid            = uid;
    event->processStart.start_action   = start_action;
    event->processStart.observed       = procp->is_real_start;

    if (procp->shared_data->cmdline)
    {
        event->processStart.path = cb_mem_cache_get_generic(procp->shared_data->cmdline, context);
    }

    // Queue it to be sent to usermode
    user_comm_send_event(event, context);
}

void event_send_last_exit(PCB_EVENT        event,
                          ProcessContext  *context)
{
    CANCEL_VOID(event);

    TRACE(DL_PROCESS, "EXIT <SEND-LAST> %s of %d by %d (reported as %d by %d)",
           (event->procInfo.path ? event->procInfo.path : "<unknown>"),
           event->procInfo.all_process_details.array[FORK].pid,
           event->procInfo.all_process_details.array[FORK_PARENT].pid,
           event->procInfo.all_process_details.array[EXEC].pid,
           event->procInfo.all_process_details.array[EXEC_PARENT].pid);

    // Queue it to be sent to usermode
    user_comm_send_event(event, context);
}

void event_send_exit(ProcessTracking *procp,
                     bool             was_last_active_process,
                     ProcessContext  *context)
{
    // We need to know if this is the last running proccess when we allocate
    //  the event because we may not be sending exits for all forks
    char      *status_msg           = "";
    PCB_EVENT  event                = factory_alloc_event(
        procp,
        was_last_active_process ? CB_EVENT_TYPE_PROCESS_LAST_EXIT : CB_EVENT_TYPE_PROCESS_EXIT,
        0,              // No message will be printed
        NULL,
        NULL,
        context);

    if (event)
    {
        if (!was_last_active_process)
        {
            // This is a fork exit, so send it now
            //  Note: This exit event may be collected by the agent before events
            //        produced by this fork.
            user_comm_send_event(event, context);
            status_msg = "<SEND> ";
        } else
        {
            process_tracking_store_exit_event(procp, event, context);
            status_msg = "<HOLD-LAST> ";
        }
    } else
    {
        status_msg = "<IGNORED> ";
    }

    if (procp)
    {
        TRACE(DL_PROCESS, "EXIT %s%s of %d by %d (reported as %d by %d)",
               status_msg,
               (procp->shared_data->path ? procp->shared_data->path : "<unknown>"),
               procp->posix_details.pid,
               procp->posix_parent_details.pid,
               procp->shared_data->exec_details.pid,
               procp->shared_data->exec_parent_details.pid);
    }
}

void event_send_block(ProcessTracking *procp,
                     uint32_t          type,
                     uint32_t          reason,
                     uint32_t          details,
                     uid_t             uid,
                     char             *cmdline,
                     ProcessContext *context)
{
    PCB_EVENT event = factory_alloc_event(
        procp,
        CB_EVENT_TYPE_PROCESS_BLOCKED,
        DL_PROCESS,
        "KILL",
        NULL,
        context);

    CANCEL_VOID(event);

    // Populate the event
    event->blockResponse.blockType            = type;
    event->blockResponse.failureReason        = TerminateFailureReasonNone;
    event->blockResponse.failureReasonDetails = 0;
    event->blockResponse.uid                  = uid;

    if (cmdline)
    {
        event->blockResponse.path = cb_mem_cache_strdup(cmdline, context);
    }


    // Queue it to be sent to usermode
    user_comm_send_event(event, context);
}

#define MSG_SIZE   200

void event_send_file(
    ProcessTracking *procp,
    CB_EVENT_TYPE    event_type,
    uint64_t         device,
    uint64_t         inode,
    CB_FILE_TYPE     file_type,
    const char *path,
    ProcessContext *context)
{
    char status_message[MSG_SIZE + 1];
    PCB_EVENT event;
    char *status_msgp = NULL;

    if (MAY_TRACE_LEVEL(DL_FILE))
    {
        status_msgp = status_message;
        snprintf(status_msgp,
             MSG_SIZE,
             " [%llu:%llu] %s by",
             device,
             inode,
             path);
        status_msgp[MSG_SIZE] = 0;
    }

    event = factory_alloc_event(
        procp,
        event_type,
        DL_FILE,
        event_type_to_str(event_type),
        status_msgp,
        context);

    CANCEL_VOID(event);

    // Populate the event
    event->fileGeneric.device    = device;
    event->fileGeneric.inode     = inode;
    event->fileGeneric.file_type = file_type;

    if (path)
    {
        event->fileGeneric.path = cb_mem_cache_strdup(path, context);
    }

    // Queue it to be sent to usermode
    user_comm_send_event(event, context);
}

void event_send_modload(
    ProcessTracking *procp,
    CB_EVENT_TYPE    event_type,
    uint64_t         device,
    uint64_t         inode,
    int64_t          base_address,
    char *path,
    ProcessContext *context)
{
    char status_message[MSG_SIZE + 1];
    PCB_EVENT event;
    char *status_msgp = NULL;

    // JANK ALERT: there is a special case where we will try to send a modload for
    // the currently execing binary in the middle of our 2 exec hooks. this results in
    // bad data and a premature exit event. we decided it was not super critical to
    // send a modload for that because we already send the process-start. eventuallly we
    // may want to make this case work if we decide to send modloads for the current elf
    // load, but for now we just drop it. We identify this case by seeing that no process
    // exec event for the current procp has been sent yet, because the exec event is
    // responsible for freeing the parent shared data.
    CANCEL_VOID(!procp->parent_shared_data);

    if (MAY_TRACE_LEVEL(DL_MODLOAD))
    {
        status_msgp = status_message;
        snprintf(status_msgp,
             MSG_SIZE,
             " [%llu:%llu]",
             device,
             inode);
        status_msgp[MSG_SIZE] = 0;
    }

    event = factory_alloc_event(
        procp,
        event_type,
        DL_MODLOAD,
        "MODLOAD",
        status_msgp,
        context);

    CANCEL_VOID(event);

    // Populate the event
    event->moduleLoad.device        = device;
    event->moduleLoad.inode         = inode;
    event->moduleLoad.baseaddress   = base_address;

    if (path)
    {
        event->moduleLoad.path = cb_mem_cache_strdup(path, context);
    }

    // Queue it to be sent to usermode
    user_comm_send_event(event, context);
}

void event_send_net_proxy(
    ProcessTracking *procp,
    char            *msg,
    CB_EVENT_TYPE    net_event_type,
    CB_SOCK_ADDR     *localAddr,
    CB_SOCK_ADDR     *remoteAddr,
    int               protocol,
    char             *actual_server,
    uint16_t          actual_port,
    void             *sk,
    ProcessContext   *context)
{
    PCB_EVENT event = factory_alloc_event(
        procp,
        net_event_type,
        0,              // No message will be printed
        NULL,
        NULL,
        context);

    CANCEL_VOID(event);

    // Populate the event
    cb_copy_sockaddr(&event->netConnect.localAddr,  localAddr);
    cb_copy_sockaddr(&event->netConnect.remoteAddr, remoteAddr);

    event->netConnect.protocol         = protocol;
    event->netConnect.actual_port      = actual_port;

    if (actual_server)
    {
        event->netConnect.actual_server = cb_mem_cache_strdup(actual_server, context);
    }

    cb_print_address(msg, sk, &localAddr->sa_addr, &remoteAddr->sa_addr);

    // Queue it to be sent to usermode
    user_comm_send_event(event, context);
}

void event_send_net(
    ProcessTracking *procp,
    char            *msg,
    CB_EVENT_TYPE    net_event_type,
    CB_SOCK_ADDR     *localAddr,
    CB_SOCK_ADDR     *remoteAddr,
    int               protocol,
    void             *sk,
    ProcessContext   *context)
{
    return event_send_net_proxy(
        procp,
        msg,
        net_event_type,
        localAddr,
        remoteAddr,
        protocol,
        NULL,
        0,
        sk,
        context);
}

void event_send_dns(
    CB_EVENT_TYPE   net_event_type,
    char           *data,
    uint32_t        len,
    ProcessContext *context)
{
    PCB_EVENT event = factory_alloc_event(
        NULL,           // The procInfo is ignored for this event type
        net_event_type,
        0,              // No message will be printed
        NULL,
        NULL,
        context);

    CANCEL_VOID(event);

    // Populate the event
    len = min_t(uint32_t, len, sizeof(event->dnsResponse.data));

    event->dnsResponse.length = len;
    event->dnsResponse.data = cb_mem_cache_alloc_generic(len, context);
    memcpy(event->dnsResponse.data, data, len);

    TRACE(DL_NET, "UDP-DNS response len:%d id:%X flags:%X",
          len, event->dnsResponse.dnsheader->id, event->dnsResponse.dnsheader->flags);

    // Queue it to be sent to usermode
    user_comm_send_event(event, context);
}
