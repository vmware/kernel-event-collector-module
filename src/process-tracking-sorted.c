// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "process-tracking-private.h"
#include "priv.h"
#include "cb-spinlock.h"

// Helper logic to sort the tracking table
typedef struct SORTED_PROCESS_TREE {
    CB_RBTREE           tree;
    cb_for_rbtree_node  rb_callback;
    void *priv;
} SORTED_PROCESS_TREE;

typedef struct SORTED_PROCESS {
    struct rb_node     node;
    time_t             start_time;
    pid_t              pid;
} SORTED_PROCESS;

static int _rbtree_compare_process_start_time(void *left, void *right);
static void _rbtree_free(void *data, ProcessContext *context);
static int _sort_process_tracking_table(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context);

void sorted_tracking_table_for_each(cb_for_rbtree_node callback, void *priv, ProcessContext *context)
{
    SORTED_PROCESS_TREE data;

    data.rb_callback = callback;
    data.priv        = priv;

    cb_rbtree_init(&data.tree,
                   offsetof(SORTED_PROCESS, start_time),
                   offsetof(SORTED_PROCESS, node),
                   _rbtree_compare_process_start_time,
                   _rbtree_free,
                   NULL,
                   context);

    hashtbl_read_for_each_generic(g_process_tracking_data.table, _sort_process_tracking_table, &data, context);

    cb_rbtree_destroy(&data.tree, context);
}

ProcessTracking *sorted_tracking_table_get_process(void *data, ProcessContext *context)
{
    if (data)
    {
        return process_tracking_get_process(((SORTED_PROCESS *)data)->pid, context);
    }
    return NULL;
}

static int _sort_process_tracking_table(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context)
{
    ProcessTracking *procp = (ProcessTracking *)nodep;
    SORTED_PROCESS_TREE *data  = (SORTED_PROCESS_TREE *)priv;

    IF_MODULE_DISABLED_GOTO(context, CATCH_DISABLED);

    // procp will be non-null while looping the entries, and null for the last call
    //  after iterating
    if (procp)
    {
        // Insert each process entry into a rb_tree sorted by the start time
        SORTED_PROCESS *value = cb_mem_cache_alloc_generic(sizeof(SORTED_PROCESS), context);

        if (value)
        {
            RB_CLEAR_NODE(&value->node);
            value->start_time = procp->posix_details.start_time;
            value->pid        = procp->pt_key.pid;
            if (!cb_rbtree_insert(&data->tree, value, context))
            {
                cb_mem_cache_free_generic(value);
            }
        }
    } else
    {
        // Walk the rb_tree.
        cb_rbtree_read_for_each(&data->tree, data->rb_callback, data->priv, context);
    }

    return ACTION_CONTINUE;

CATCH_DISABLED:
    return ACTION_STOP;
}

// Compare function for the rb_tree
static int _rbtree_compare_process_start_time(void *left, void *right)
{
    time_t *left_key  = (time_t *)left;
    time_t *right_key = (time_t *)right;

    if (left_key && right_key)
    {
        if (*left_key < *right_key)
        {
            return -1;
        } else if (*left_key > *right_key)
        {
            return 1;
        } else if (*left_key == *right_key)
        {
            return 0;
        }
    }
    return -2;
}

static void _rbtree_free(void *data, ProcessContext *context)
{
    cb_mem_cache_free_generic(data);
}
