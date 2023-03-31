// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "event-factory.h"
#include "net-helper.h"
#include "priv.h"
#include "mem-alloc.h"

const char *ec_StartAction_ToString(int start_action)
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

PCB_EVENT ec_factory_alloc_event(
    ProcessHandle * process_handle,
    CB_EVENT_TYPE   eventType,
    int             trace_level,
    const char     *type_msg,
    const char     *status_msg,
    ProcessContext *context)
{
    PCB_EVENT event = NULL;

    if (process_handle && type_msg && MAY_TRACE_LEVEL(trace_level))
    {
        TRACE(trace_level, "%s%s %s of %d by %d (reported as %d:%ld by %d)",
              type_msg,
              (status_msg ? status_msg : ""),
              SAFE_STRING(ec_process_path(process_handle)),
              ec_process_posix_identity(process_handle)->posix_details.pid,
              ec_process_posix_identity(process_handle)->posix_parent_details.pid,
              ec_process_exec_identity(process_handle)->exec_details.pid,
              ec_process_exec_identity(process_handle)->exec_details.start_time,
              ec_process_exec_identity(process_handle)->exec_parent_details.pid);
    }

    // This will return a NULL event if we are configured to not send this event type
    event = ec_alloc_event(eventType, context);

    // We still call this even for a NULL event to give the process_tracking a chance
    //  to clean up any private data
    ec_process_tracking_set_event_info(process_handle, eventType, event, context);

    return event;
}

void ec_event_send_start(
    ProcessHandle * process_handle,
    uid_t           uid,
    int             start_action,
    ProcessContext *context)
{
    PCB_EVENT event = NULL;

    CANCEL_VOID(process_handle);

    event = ec_factory_alloc_event(
        process_handle,
        start_action != CB_PROCESS_START_BY_FORK ? CB_EVENT_TYPE_PROCESS_START_EXEC : CB_EVENT_TYPE_PROCESS_START_FORK,
        DL_PROCESS,
        ec_StartAction_ToString(start_action),
        (process_handle && ec_process_posix_identity(process_handle)->is_real_start ? "" : " <FAKE>"),
        context);

    CANCEL_VOID(event);

    // Populate the event
    event->processStart.uid            = uid;
    event->processStart.start_action   = start_action;
    event->processStart.observed       = ec_process_posix_identity(process_handle)->is_real_start;

    event->processStart.path  = ec_mem_get(ec_process_cmdline(process_handle), context);// take reference
    event->processStart.path_size = ec_mem_size(event->processStart.path);

    ec_send_event(event, context);
}

void ec_event_send_discover(
    ProcessHandle  * process_handle,
    uid_t            uid,
    ProcessContext  *context)
{
    PCB_EVENT event = NULL;

    CANCEL_VOID(process_handle);

    event = ec_factory_alloc_event(
        process_handle,
        CB_EVENT_TYPE_DISCOVER,
        0, // No message will be printed
        NULL,
        NULL,
        context);

    CANCEL_VOID(event);

    // Populate the event
    event->processDiscover.uid            = uid;
    event->processDiscover.observed       = ec_process_posix_identity(process_handle)->is_real_start;

    event->processDiscover.path  = ec_mem_get(ec_process_cmdline(process_handle), context);// take reference
    event->processDiscover.path_size = ec_mem_size(event->processDiscover.path);

    memcpy(&event->processDiscover.exec, &ec_process_exec_identity(process_handle)->exec_details, sizeof(ProcessDetails));
    memcpy(&event->processDiscover.exec_parent, &ec_process_exec_identity(process_handle)->exec_parent_details, sizeof(ProcessDetails));

    ec_send_event(event, context);
}

void ec_event_send_discover_complete(ProcessContext  *context)
{
    PCB_EVENT event = NULL;

    event = ec_factory_alloc_event(
        NULL,
        CB_EVENT_TYPE_DISCOVER_COMPLETE,
        0, // No message will be printed
        NULL,
        NULL,
        context);

    CANCEL_VOID(event);

    ec_send_event(event, context);
}

void ec_event_send_discover_flush(ProcessContext  *context)
{
    PCB_EVENT event = NULL;

    event = ec_factory_alloc_event(
        NULL,
        CB_EVENT_TYPE_DISCOVER_FLUSH,
        0, // No message will be printed
        NULL,
        NULL,
        context);

    CANCEL_VOID(event);

    ec_send_event(event, context);
}

void ec_event_send_last_exit(PCB_EVENT        event,
                          ProcessContext  *context)
{
    CANCEL_VOID(event);

    TRACE(DL_PROCESS, "EXIT <SEND-LAST> %s of %d by %d (reported as %d:%ld by %d)",
           SAFE_STRING(event->procInfo.path),
           event->procInfo.all_process_details.array[FORK].pid,
           event->procInfo.all_process_details.array[FORK_PARENT].pid,
           event->procInfo.all_process_details.array[EXEC].pid,
           event->procInfo.all_process_details.array[EXEC].start_time,
           event->procInfo.all_process_details.array[EXEC_PARENT].pid);

    ec_send_event(event, context);
}

void ec_event_send_exit(
    ProcessHandle * process_handle,
    bool            was_last_active_process,
    ProcessContext *context)
{
    // We need to know if this is the last running proccess when we allocate
    //  the event because we may not be sending exits for all forks
    PCB_EVENT  event                = ec_factory_alloc_event(
        process_handle,
        was_last_active_process ? CB_EVENT_TYPE_PROCESS_LAST_EXIT : CB_EVENT_TYPE_PROCESS_EXIT,
        0,              // No message will be printed
        NULL,
        NULL,
        context);

    ec_send_event(event, context);

    if (MAY_TRACE_LEVEL(DL_PROCESS))
    {
        TRACE(DL_PROCESS, "EXIT %s %s of %d by %d (reported as %d:%ld by %d)",
              event ? "<SENT>" : "<IGNORED>",
              SAFE_STRING(ec_process_path(process_handle)),
              ec_process_posix_identity(process_handle)->posix_details.pid,
              ec_process_posix_identity(process_handle)->posix_parent_details.pid,
              ec_process_exec_identity(process_handle)->exec_details.pid,
              ec_process_exec_identity(process_handle)->exec_details.start_time,
              ec_process_exec_identity(process_handle)->exec_parent_details.pid);
    }
}

void ec_event_send_block(
    ProcessHandle * process_handle,
    uint32_t        type,
    uint32_t        reason,
    uint32_t        details,
    uid_t           uid,
    char           *cmdline,
    ProcessContext *context)
{
    PCB_EVENT event = ec_factory_alloc_event(
        process_handle,
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
        event->blockResponse.path = ec_mem_strdup(cmdline, context);
        event->blockResponse.path_size = ec_mem_size(event->blockResponse.path);
    }

    ec_send_event(event, context);
}

#define MSG_SIZE   200

void ec_event_send_file(
    ProcessHandle  * process_handle,
    CB_EVENT_TYPE    event_type,
    PathData        *path_data,
    ProcessContext  *context)
{
    char status_message[MSG_SIZE + 1];
    PCB_EVENT event;
    char *status_msgp = NULL;

    CANCEL_VOID(path_data);

    if (MAY_TRACE_LEVEL(DL_FILE))
    {
        status_msgp = status_message;
        snprintf(status_msgp,
                 MSG_SIZE,
                 " [%llu:%llu:%llx] %s by",
                 path_data->key.device,
                 path_data->key.inode,
                 path_data->fs_magic,
                 SAFE_STRING(path_data->path));
        status_msgp[MSG_SIZE] = 0;
    }

    event = ec_factory_alloc_event(
        process_handle,
        event_type,
        DL_FILE,
        ec_event_type_to_str(event_type),
        status_msgp,
        context);

    CANCEL_VOID(event);

    // Populate the event
    event->fileGeneric.device    = path_data->key.device;
    event->fileGeneric.inode     = path_data->key.inode;
    event->fileGeneric.fs_magic  = path_data->fs_magic;

    if (path_data->path_found)
    {
        event->fileGeneric.path = ec_mem_get(path_data->path, context);
        event->fileGeneric.path_size = ec_mem_size(path_data->path);
    }

    ec_send_event(event, context);
}

void ec_event_send_modload(
    ProcessHandle  * process_handle,
    CB_EVENT_TYPE    event_type,
    uint64_t         device,
    uint64_t         inode,
    int64_t          base_address,
    char            *path,
    ProcessContext  *context)
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
    // exec event for the current posix_identity has been sent yet, because the exec event is
    // responsible for freeing the parent shared data.
    CANCEL_VOID(process_handle && !ec_exec_identity(&ec_process_posix_identity(process_handle)->temp_exec_handle));

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

    event = ec_factory_alloc_event(
        process_handle,
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
        event->moduleLoad.path = ec_mem_strdup(path, context);
        event->moduleLoad.path_size = ec_mem_size(event->moduleLoad.path);
    }

    ec_send_event(event, context);
}

void ec_event_send_net_proxy(
    ProcessHandle   * process_handle,
    const char       *msg,
    CB_EVENT_TYPE     net_event_type,
    CB_SOCK_ADDR     *localAddr,
    CB_SOCK_ADDR     *remoteAddr,
    int               protocol,
    char             *actual_server,
    uint16_t          actual_port,
    void             *sk,
    ProcessContext   *context)
{
    PCB_EVENT event = ec_factory_alloc_event(
        process_handle,
        net_event_type,
        DL_NET,
        msg,
        NULL,
        context);

    CANCEL_VOID(event);

    if (MAY_TRACE_LEVEL(DL_NET))
    {
        ec_print_address(msg, sk, &localAddr->sa_addr, &remoteAddr->sa_addr);
    }

    // Populate the event
    ec_copy_sockaddr(&event->netConnect.localAddr,  localAddr);
    ec_copy_sockaddr(&event->netConnect.remoteAddr, remoteAddr);

    event->netConnect.protocol         = protocol;
    event->netConnect.actual_port      = actual_port;

    if (actual_server)
    {
        event->netConnect.actual_server = ec_mem_strdup(actual_server, context);
        event->netConnect.server_size = ec_mem_size(event->netConnect.actual_server);
    }

    ec_send_event(event, context);
}

void ec_event_send_net(
    ProcessHandle   * process_handle,
    const char       *msg,
    CB_EVENT_TYPE     net_event_type,
    CB_SOCK_ADDR     *localAddr,
    CB_SOCK_ADDR     *remoteAddr,
    int               protocol,
    void             *sk,
    ProcessContext   *context)
{
    return ec_event_send_net_proxy(
        process_handle,
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

void ec_event_send_dns(
    CB_EVENT_TYPE          net_event_type,
    CB_EVENT_DNS_RESPONSE *response,
    ProcessContext        *context)
{
    PCB_EVENT event;

    CANCEL_VOID(response);

    event = ec_factory_alloc_event(
        NULL,           // The procInfo is ignored for this event type
        net_event_type,
        0,              // No message will be printed
        NULL,
        NULL,
        context);
    CANCEL_VOID(event);

    // Populate the event
    memcpy(&event->dnsResponse, response, sizeof(CB_EVENT_DNS_RESPONSE));

    // Clear this from the input because it is now owned by the event.
    response->records = NULL;

    ec_send_event(event, context);
}

const char *ec_EventType_ToString(int event_type)
{
    switch (event_type)
    {
    case CB_EVENT_TYPE_PROCESS_START: return "START"; break;
    case CB_EVENT_TYPE_PROCESS_EXIT: return "EXIT"; break;
    case CB_EVENT_TYPE_DISCOVER: return "DISCOVER"; break;
    case CB_EVENT_TYPE_DISCOVER_COMPLETE: return "DISCOVER COMPLETE"; break;
    case CB_EVENT_TYPE_DISCOVER_FLUSH: return "DISCOVER FLUSH"; break;
    case CB_EVENT_TYPE_MODULE_LOAD: return "MODULE LOAD"; break;
    case CB_EVENT_TYPE_FILE_CREATE: return "FILE CREATE"; break;
    case CB_EVENT_TYPE_FILE_DELETE: return "FILE DELETE"; break;
    case CB_EVENT_TYPE_FILE_WRITE: return "FILE WRITE"; break;
    case CB_EVENT_TYPE_FILE_CLOSE: return "FILE CLOSE"; break;
    case CB_EVENT_TYPE_FILE_OPEN: return "FILE OPEN"; break;
    case CB_EVENT_TYPE_NET_CONNECT_PRE: return "NET CONECT PRE"; break;
    case CB_EVENT_TYPE_NET_CONNECT_POST: return "NET CONNECT POST"; break;
    case CB_EVENT_TYPE_NET_ACCEPT: return "NET ACCEPT"; break;
    case CB_EVENT_TYPE_DNS_RESPONSE: return "DNS RESPONSE"; break;
    case CB_EVENT_TYPE_PROCESS_BLOCKED: return "BLOCK"; break;
    case CB_EVENT_TYPE_WEB_PROXY: return "WEB PROXY"; break;
    case CB_EVENT_TYPE_HEARTBEAT: return "HEARTBEAT"; break;
    case CB_EVENT_TYPE_PROCESS_START_FORK: return "FORK"; break;
    case CB_EVENT_TYPE_PROCESS_START_EXEC: return "EXEC"; break;
    case CB_EVENT_TYPE_PROCESS_LAST_EXIT: return "LAST EXIT"; break;
    default:
        break;
    }
    return "UNKNOWN";
}
