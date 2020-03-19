// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include <linux/time.h>
#include <linux/gfp.h>
#include "priv.h"
#include "mem-cache.h"
#include "cb-banning.h"
#include "process-tracking.h"

#pragma pack(push, 1)
typedef struct _logger_work {
    struct  work_struct     work;

    struct cn_msg           cnmsg;
    struct CB_EVENT         event;
}
logger_work, *plogger_work;
#pragma pack(pop)

static CB_MEM_CACHE s_event_cache;

static const struct timespec null_time = {0, 0};

uint64_t to_windows_timestamp(const struct timespec *tv)
{
    return TO_WIN_TIME(tv->tv_sec, tv->tv_nsec);
}

struct timespec get_current_timespec(void)
{
    struct timespec     current_time;

    getnstimeofday(&current_time);
    return current_time;
}

time_t get_current_time(void)
{
    struct timespec     current_time;

    getnstimeofday(&current_time);
    return to_windows_timestamp(&current_time);
}

time_t get_null_time(void)
{
    return TO_WIN_TIME(0, 0);
}

void logger_free_event(PCB_EVENT event, ProcessContext *context)
{
    if (event)
    {
        CB_EVENT_NODE *node = container_of(event, CB_EVENT_NODE, data);

        // Free the stored process data
        //  This may cause a stored exit event to be sent if this is the last event
        //  for a process.
        logger_set_process_data(event, NULL, context);

        cb_mem_cache_free_generic(event->procInfo.path);
        event->procInfo.path = NULL;

        cb_mem_cache_free_generic(event->generic_data.data);
        event->generic_data.data = NULL;

        cb_mem_cache_free(&s_event_cache, node, context);
    }
}

void logger_set_process_data(PCB_EVENT event, void *process_data, ProcessContext *context)
{
    if (event)
    {
        CB_EVENT_NODE *node = container_of(event, CB_EVENT_NODE, data);

        // If we have something stored free it now
        process_tracking_release_shared_data_ref(node->process_data, context);

        // Save the process data in the event node and increase the ref
        //  We don't actually do anything with this.  We only release it later.
        node->process_data = process_tracking_get_shared_data_ref(process_data, context);
    }
}

bool should_log(CB_EVENT_TYPE eventType)
{
    switch (eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START_FORK:
        switch (g_driver_config.processes)
        {
        case COLLAPSED_EXITS_ALL_FORKS:
        case ALL_FORKS_AND_EXITS:
            return true;
        case EXECS_ONLY:
        case COLLAPSED_EXITS_NO_FORKS:
        case DISABLE:
        default:
            return false;
        }
        break;

    case CB_EVENT_TYPE_PROCESS_START_EXEC:
        return g_driver_config.processes != DISABLE;
        break;

    case CB_EVENT_TYPE_PROCESS_EXIT:
        switch (g_driver_config.processes)
        {
        case ALL_FORKS_AND_EXITS:
            return true;
        default:
            return false;
        }
        break;

    case CB_EVENT_TYPE_PROCESS_LAST_EXIT:
        switch (g_driver_config.processes)
        {
        case COLLAPSED_EXITS_ALL_FORKS:
        case ALL_FORKS_AND_EXITS:
        case COLLAPSED_EXITS_NO_FORKS:
            return true;
        case EXECS_ONLY:
        case DISABLE:
        default:
            return false;
        }
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
        return g_driver_config.module_loads == ENABLE;

    case CB_EVENT_TYPE_FILE_CREATE:
    case CB_EVENT_TYPE_FILE_DELETE:
    case CB_EVENT_TYPE_FILE_WRITE:
    case CB_EVENT_TYPE_FILE_CLOSE:
    case CB_EVENT_TYPE_FILE_OPEN:
        return g_driver_config.file_mods == ENABLE;

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
    case CB_EVENT_TYPE_NET_CONNECT_POST:
    case CB_EVENT_TYPE_NET_ACCEPT:
    case CB_EVENT_TYPE_DNS_RESPONSE:
        return g_driver_config.net_conns == ENABLE;

    case CB_EVENT_TYPE_PROCESS_BLOCKED:
    case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
    case CB_EVENT_TYPE_HEARTBEAT:
    case CB_EVENT_TYPE_WEB_PROXY:
        return true;

    default:
        TRACE(DL_WARNING, "Unknown shouldlog event type %d", eventType);
        return true;
    }
}


bool shouldExcludeByUID(ProcessContext *context, uid_t uid)
{
    if (g_cb_server_uid == uid)
    {
        return true;
    }

    return cbIngoreUid(context, uid);
}

PCB_EVENT logger_alloc_event(CB_EVENT_TYPE eventType, ProcessContext *context)
{
    CB_EVENT_NODE *node = NULL;
    PCB_EVENT event = NULL;
    uid_t uid = GET_UID();
    CB_EVENT_TYPE resolvedEventType = eventType;

    // We use some semi-private event types to provide some extra granularity.
    //  Depending on the config structure, the should_log function may reject the
    //  event. The collector does not care about this extra granularitiy, so once
    //  we know the event should be logged, we set it to the more generic event type.
    TRY(should_log(eventType));
    switch (eventType)
    {
    case CB_EVENT_TYPE_PROCESS_LAST_EXIT:
        resolvedEventType = CB_EVENT_TYPE_PROCESS_EXIT;
        break;
    case CB_EVENT_TYPE_PROCESS_START_FORK:
    case CB_EVENT_TYPE_PROCESS_START_EXEC:
        resolvedEventType = CB_EVENT_TYPE_PROCESS_START;
        break;
    default:
        break;
    }

    TRY(!shouldExcludeByUID(context, uid));

    node = (CB_EVENT_NODE *)cb_mem_cache_alloc(&s_event_cache, context);

    TRY_DO(node, {
        TRACE(DL_WARNING, "Error allocating event with mode %s", IS_ATOMIC(context) ? "ATOMIC" : "KERNEL");
    });

    node->process_data = NULL;
    event              = &node->data;

    event->apiVersion = CB_APP_API_VERSION;
    event->eventType  = resolvedEventType;
    event->canary     = 0;

    event->procInfo.event_time  = get_current_time();
    event->procInfo.path_found = false;
    event->procInfo.path       = NULL;
    event->generic_data.data   = NULL;
    memset(&event->procInfo.all_process_details, 0, sizeof(AllProcessDetails));

CATCH_DEFAULT:
    return event;
}

void logger_free_event_on_error(PCB_EVENT event, ProcessContext *context)
{
    logger_free_event(event, context);
}

bool logger_initialize(ProcessContext *context)
{
    TRACE(DL_INFO, "Initializing Logger");
    TRACE(DL_INFO, "CB_EVENT size is %ld (0x%lx)", sizeof(struct CB_EVENT), sizeof(struct CB_EVENT));

    if (!cb_mem_cache_create(&s_event_cache, "event_cache", sizeof(CB_EVENT_NODE), context))
    {
        return false;
    }

    return true;
}

void logger_shutdown(ProcessContext *context)
{
    cb_mem_cache_destroy(&s_event_cache, context, NULL);
}

