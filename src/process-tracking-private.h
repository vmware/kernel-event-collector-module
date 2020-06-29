#pragma once

#include "process-tracking.h"
#include "rbtree-helper.h"

typedef struct process_tracking_data {
    uint64_t      op_cnt;
    uint64_t      create;
    uint64_t      exit;
    uint64_t      create_by_fork;
    uint64_t      create_by_exec;

    HashTbl      *table;
    CB_MEM_CACHE  shared_data_cache;
} process_tracking_data;

extern process_tracking_data g_process_tracking_data;

void process_tracking_update_op_cnts(ProcessTracking *procp, CB_EVENT_TYPE event_type, int action);
void sorted_tracking_table_for_each(cb_for_rbtree_node callback, void *priv, ProcessContext *context);
ProcessTracking *sorted_tracking_table_get_process(void *data);
const char *process_tracking_get_proc_name(const char *path);

void process_tracking_set_shared_data(ProcessTracking *procp, SharedTrackingData *shared_data, ProcessContext *context);
void process_tracking_set_parent_shared_data(ProcessTracking *procp, SharedTrackingData *shared_data, ProcessContext *context);

// #define _REF_DEBUGGING
#ifdef _REF_DEBUGGING
    #define TRACE_IF_REF_DEBUGGING(...)  TRACE(__VA_ARGS__)
#else
    #define TRACE_IF_REF_DEBUGGING(...)
#endif
