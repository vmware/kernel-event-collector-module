// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "file-process-tracking.h"
#include "process-tracking.h"
#include "hash-table-generic.h"
#include "priv.h"
#include "rbtree-helper.h"

int _ec_file_process_tree_compare(void *left, void *right);
void _ec_file_process_tree_put_ref(void *data, ProcessContext *context);
void _ec_file_process_tree_get_ref(void *data, ProcessContext *context);

static CB_MEM_CACHE s_file_process_cache;

FILE_PROCESS_VALUE *ec_file_process_alloc(ProcessContext *context);


bool ec_file_process_tracking_init(ProcessContext *context)
{
    return ec_mem_cache_create(&s_file_process_cache, "file_process_cache", sizeof(FILE_PROCESS_VALUE), context);
}

void ec_file_process_tracking_shutdown(ProcessContext *context)
{
    ec_mem_cache_destroy(&s_file_process_cache, context, NULL);
}

FILE_PROCESS_VALUE *ec_file_process_alloc(ProcessContext *context)
{
    FILE_PROCESS_VALUE *value = (FILE_PROCESS_VALUE *)ec_mem_cache_alloc(&s_file_process_cache, context);

    if (value)
    {
        RB_CLEAR_NODE(&value->node);
    }

    return value;
}

void ec_file_process_free(FILE_PROCESS_VALUE *value, ProcessContext *context)
{
    if (value)
    {
        if (value->path)
        {
            ec_mem_cache_free_generic(value->path);
            value->path = NULL;
        }
        ec_mem_cache_free(&s_file_process_cache, value, context);
    }
}


FILE_PROCESS_VALUE *ec_file_process_status_open(
    uint64_t       device,
    uint64_t       inode,
    uint32_t       pid,
    char *path,
    bool           isSpecialFile,
    ProcessContext *context)
{
    FILE_PROCESS_VALUE *value = NULL;
    FILE_TREE_HANDLE tree_handle;
    FILE_PROCESS_KEY key = { device, inode };
    char *process_path = NULL;

    TRY(ec_process_tracking_get_file_tree(pid, &tree_handle, context));

    // This will increase the ref count
    value = ec_rbtree_search(tree_handle.tree, &key, context);
    if (!value)
    {
        value = ec_file_process_alloc(context);
        TRY(value);

        // Initialize the reference count
        atomic64_set(&value->reference_count, 1);

        value->key.device    = device;
        value->key.inode     = inode;
        value->pid           = pid;
        value->isSpecialFile = isSpecialFile;
        value->didReadType   = false;
        value->status        = OPENED;
        value->path          = NULL;

        if (path && *path)
        {
            size_t len = strlen(path);

            value->path = ec_mem_cache_alloc_generic(len + 1, context);
            if (value->path)
            {
                value->path[0] = 0;
                strncat(value->path, path, len);
            }
        }

        // The insert will take a reference
        if (!ec_rbtree_insert(tree_handle.tree, value, context))
        {
            // If the insert failed we free the local reference and clear
            //  value
            ec_file_process_put_ref(value, context);
            value = NULL;
            if (MAY_TRACE_LEVEL(DL_INFO))
            {
                if (tree_handle.exec_identity)
                {
                    process_path = ec_process_tracking_get_path(tree_handle.exec_identity, context);
                }

                // We are racing against other threads or processes
                // to insert a similar entry on the same rb_tree.
                TRACE(DL_INFO, "File entry already exists: [%llu:%llu] %s pid:%u (%s)",
                    device, inode, path ? path : "(path unknown)", pid, process_path ? process_path : "<unknown>");
                ec_process_tracking_put_path(process_path, context);
            }
        }
    }

CATCH_DEFAULT:
    ec_process_tracking_put_file_tree(&tree_handle, context);

    // Return holding a reference
    return value;
}

FILE_PROCESS_VALUE *ec_file_process_status(uint64_t device, uint64_t inode, uint32_t pid, ProcessContext *context)
{
    FILE_PROCESS_VALUE *value = NULL;
    FILE_TREE_HANDLE tree_handle;
    FILE_PROCESS_KEY key = {device, inode};

    TRY(ec_process_tracking_get_file_tree(pid, &tree_handle, context));

    // This take a local reference and return it below
    value = ec_rbtree_search(tree_handle.tree, &key, context);

CATCH_DEFAULT:
    ec_process_tracking_put_file_tree(&tree_handle, context);

    return value;
}

void ec_file_process_status_close(uint64_t device, uint64_t inode, uint32_t pid, ProcessContext *context)
{
    FILE_TREE_HANDLE tree_handle;
    FILE_PROCESS_KEY key = {device, inode};

    CANCEL_VOID(ec_process_tracking_get_file_tree(pid, &tree_handle, context));

    ec_rbtree_delete_by_key(tree_handle.tree, &key, context);

    ec_process_tracking_put_file_tree(&tree_handle, context);
}

void ec_file_process_get_ref(FILE_PROCESS_VALUE *value, ProcessContext *context)
{
    if (value)
    {
        atomic64_inc(&value->reference_count);
    }
}

void ec_file_process_put_ref(FILE_PROCESS_VALUE *value, ProcessContext *context)
{
    CANCEL_VOID(value);

    IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(&value->reference_count, {
        ec_file_process_free(value, context);
    });
}

// When a process exits we want to go over the list of open files that it owns and
//  remove them.
void ec_check_open_file_list_on_exit(CB_RBTREE *tree, ProcessContext *context)
{
    if (tree)
    {
         ec_rbtree_clear(tree, context);
    }
}

void ec_file_process_tree_init(void **tree, ProcessContext *context)
{
    if (tree)
    {
        *tree = ec_mem_cache_alloc_generic(sizeof(CB_RBTREE), context);
        if (*tree)
        {
            ec_rbtree_init(*tree,
                           offsetof(FILE_PROCESS_VALUE, key),
                           offsetof(FILE_PROCESS_VALUE, node),
                           _ec_file_process_tree_compare,
                           _ec_file_process_tree_get_ref,
                           _ec_file_process_tree_put_ref,
                           context);
        }
    }
}

void ec_file_process_tree_destroy(void **tree, ProcessContext *context)
{
    if (tree && *tree)
    {
        ec_rbtree_destroy(*tree, context);
        ec_mem_cache_free_generic(*tree);
        *tree = NULL;
    }
}

// This helper function is used by the rbtree to find nodes
int _ec_file_process_tree_compare(void *left, void *right)
{
    FILE_PROCESS_KEY *left_key  = (FILE_PROCESS_KEY *)left;
    FILE_PROCESS_KEY *right_key = (FILE_PROCESS_KEY *)right;

    if (left_key && right_key)
    {
        bool isDeviceEqual = (left_key->device == right_key->device);

        if (left_key->device < right_key->device || (isDeviceEqual && left_key->inode < right_key->inode))
        {
            return -1;
        } else if (left_key->device > right_key->device || (isDeviceEqual && left_key->inode > right_key->inode))
        {
            return 1;
        } else if (isDeviceEqual && left_key->inode == right_key->inode)
        {
            return 0;
        }
    }
    return -2;
}

void _ec_file_process_tree_get_ref(void *data, ProcessContext *context)
{
    ec_file_process_get_ref(data, context);
}

void _ec_file_process_tree_put_ref(void *data, ProcessContext *context)
{
    ec_file_process_put_ref(data, context);
}

void __ec_for_each_file_tree(void *tree, void *priv, ProcessContext *context);
void __ec_show_file_tracking_table(void *data, void *priv, ProcessContext *context);

struct _tree_priv {
    struct seq_file *m;
    uint64_t         count;
};

int ec_file_track_show_table(struct seq_file *m, void *v)
{

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    seq_printf(m, "%40s | %10s | %10s | %6s | %10s | %10s |\n",
                   "Path", "Device", "Inode", "PID", "Is Special", "Count");

    ec_process_tracking_for_each_file_tree(__ec_for_each_file_tree, m, &context);

    return 0;
}

void __ec_for_each_file_tree(void *tree, void *priv, ProcessContext *context)
{
    if (tree)
    {
        struct _tree_priv tree_priv = {priv, atomic64_read(&((CB_RBTREE *)tree)->count)};

        ec_rbtree_read_for_each(tree, __ec_show_file_tracking_table, &tree_priv, context);
    }
}

void __ec_show_file_tracking_table(void *data, void *priv, ProcessContext *context)
{
    if (data && priv)
    {
        FILE_PROCESS_VALUE *value = (FILE_PROCESS_VALUE *)data;
        struct _tree_priv *local_priv = (struct _tree_priv *)priv;

        seq_printf(local_priv->m, "%40s | %10llu | %10llu | %6d | %10s| %10llu |\n",
                      value->path,
                      value->key.device,
                      value->key.inode,
                      value->pid,
                      (value->isSpecialFile ? "YES" : "NO"),
                      local_priv->count);
    }
}
