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

int __ec_hashtbl_for_each_file_tree(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context);

bool ec_process_tracking_get_file_tree(pid_t pid, FILE_TREE_HANDLE *handle, ProcessContext *context)
{
    ExecIdentity *exec_identity = NULL;
    PosixIdentity *posix_identity = NULL;

    TRY(handle);
    handle->tree = NULL;
    handle->exec_identity = NULL;

    posix_identity = ec_process_tracking_get_process(pid, context);

    TRY(posix_identity);
    exec_identity = ec_process_tracking_get_exec_identity(posix_identity, context);

    if (exec_identity)
    {
        // This holds the ref we just got
        handle->exec_identity = exec_identity;
        handle->tree        = exec_identity->tracked_files;
    }

    ec_process_tracking_put_process(posix_identity, context);

    return true;

CATCH_DEFAULT:
    return false;
}

void ec_process_tracking_put_file_tree(FILE_TREE_HANDLE *handle, ProcessContext *context)
{
    if (handle)
    {
        ec_process_tracking_put_exec_identity(handle->exec_identity, context);
        handle->tree = NULL;
        handle->exec_identity = NULL;
    }
}

void ec_process_tracking_for_each_file_tree(process_tracking_for_each_tree_callback callback, void *priv, ProcessContext *context)
{
    // TODO: Improve the tree print logic
    //       This loops over all process tracking nodes and prints the tree inside the shared struct.
    //       The problem here as that the shared struct can/wil be referenced multiple times.  We need
    //       to add some logic that prints it only once.
    struct for_each_priv local_priv = { callback, priv };

    ec_hashtbl_read_for_each_generic(g_process_tracking_data.table, __ec_hashtbl_for_each_file_tree, &local_priv, context);
}

// Note: This function is used as a callback by ec_hashtbl_read_for_each_generic called from
//       ec_process_tracking_for_each, and is called from inside a spinlock.
//       Therefore, in the future if modifications are required be aware that any function call that may
//       sleep should be avoided.
int __ec_hashtbl_for_each_file_tree(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context)
{
    PosixIdentity *posix_identity      = NULL;
    ExecIdentity *exec_identity = NULL;
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

    posix_identity = (PosixIdentity *)nodep;
    exec_identity = ec_process_tracking_get_exec_identity(posix_identity, context);
    local_priv = (struct for_each_priv *)priv;

    if (exec_identity)
    {
        // TODO: How well is tracked_files protected
        ((process_tracking_for_each_tree_callback) local_priv->callback)(
            exec_identity->tracked_files,
            local_priv->priv,
            context);
    }
    ec_process_tracking_put_exec_identity(exec_identity, context);
    return ACTION_CONTINUE;
}
