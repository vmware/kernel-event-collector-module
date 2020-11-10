// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "process-tracking-private.h"
#include "cb-test.h"
#include "event-factory.h"
#include "priv.h"

// We have several layers of private data to pass to various callbacks
struct for_each_priv {
    void *callback;
    void *priv;
};

static int __hashtbl_for_each_file_tree(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context);

bool process_tracking_get_file_tree(pid_t pid, FILE_TREE_HANDLE *handle, ProcessContext *context)
{
    SharedTrackingData *shared_data = NULL;
    ProcessTracking *procp = NULL;

    TRY(handle);
    handle->tree = NULL;
    handle->shared_data = NULL;

    procp = process_tracking_get_process(pid, context);

    TRY(procp);
    shared_data = process_tracking_get_shared_data_ref(procp->shared_data, context);

    if (shared_data)
    {
        // This holds the ref we just got
        handle->shared_data = shared_data;
        handle->tree        = shared_data->tracked_files;
    }

    process_tracking_put_process(procp, context);

    return true;

CATCH_DEFAULT:
    return false;
}

void process_tracking_put_file_tree(FILE_TREE_HANDLE *handle, ProcessContext *context)
{
    if (handle)
    {
        process_tracking_release_shared_data_ref(handle->shared_data, context);
        handle->tree = NULL;
        handle->shared_data = NULL;
    }
}

void process_tracking_for_each_file_tree(process_tracking_for_each_tree_callback callback, void *priv, ProcessContext *context)
{
    // TODO: Improve the tree print logic
    //       This loops over all process tracking nodes and prints the tree inside the shared struct.
    //       The problem here as that the shared struct can/wil be referenced multiple times.  We need
    //       to add some logic that prints it only once.
    struct for_each_priv local_priv = { callback, priv };

    hashtbl_read_for_each_generic(g_process_tracking_data.table, __hashtbl_for_each_file_tree, &local_priv, context);
}

// Note: This function is used as a callback by hashtbl_read_for_each_generic called from
//       process_tracking_for_each, and is called from inside a spinlock.
//       Therefore, in the future if modifications are required be aware that any function call that may
//       sleep should be avoided.
static int __hashtbl_for_each_file_tree(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context)
{
    ProcessTracking *procp      = NULL;
    struct for_each_priv *local_priv = NULL;

    // NULL when hashtbl iterator has signal a stop.
    // No harm in returning ACTION_STOP here.
    if (NULL == nodep)
    {
        return ACTION_STOP;
    }

    // Saftey first
    if (NULL == priv)
    {
        TRACE(DL_ERROR, "%s:%d NULL ptr provided as function argument [%p=nodep %p=priv]. Bailing...\n",
                         __func__, __LINE__, nodep, priv);
        return ACTION_STOP;
    }

    procp = (ProcessTracking *)nodep;
    local_priv = (struct for_each_priv *)priv;

    ((process_tracking_for_each_tree_callback)local_priv->callback)(procp->shared_data->tracked_files, local_priv->priv, context);
    return ACTION_CONTINUE;
}
