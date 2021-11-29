// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 VMware Inc.  All rights reserved.

#include "path-cache.h"
#include "file-helper.h"
#include "module_state.h"
#include "task-helper.h"
#include "cb-test.h"
#include "priv.h"

static HashTbl * s_file_cache;

void __ec_path_cache_delete_callback(void *data, ProcessContext *context);


bool ec_path_cache_init(ProcessContext *context)
{
    s_file_cache = ec_hashtbl_init_generic(
        context,
        1024,
        sizeof(PathData),
        0,
        "file_path_cache",
        sizeof(PathKey),
        offsetof(PathData, key),
        offsetof(PathData, node),
        offsetof(PathData, reference_count),
        HASHTBL_DISABLE_LRU,
        __ec_path_cache_delete_callback,
        NULL);

    return s_file_cache != NULL;
}

void ec_path_cache_shutdown(ProcessContext *context)
{
    ec_hashtbl_shutdown_generic(s_file_cache, context);
}

PathData *ec_path_cache_find(
    uint64_t            ns_id,
    uint64_t            device,
    uint64_t            inode,
    ProcessContext     *context)
{
    PathKey key = { ns_id, device, inode };

    return ec_hashtbl_get_generic(s_file_cache, &key, context);
}


PathData *ec_path_cache_get(
    PathData           *path_data,
    ProcessContext     *context)
{
    return ec_hashtbl_get_generic_ref(s_file_cache, path_data, context);
}

PathData *ec_path_cache_add(
    uint64_t            ns_id,
    uint64_t            device,
    uint64_t            inode,
    char               *path,
    uint64_t            fs_magic,
    ProcessContext     *context)
{
    PathData *value = NULL;

    if (path)
    {
        value = ec_hashtbl_alloc_generic(s_file_cache, context);
        CANCEL(value, NULL);

        value->key.ns_id = ns_id;
        value->key.device = device;
        value->key.inode = inode;
        value->path = ec_mem_cache_get_generic(path, context);
        value->path_found = !!path; // It is possible that the path will be NULL now but set later
        value->file_id = ec_get_current_time(); // Use this as a unique ID
        value->is_special_file = ec_is_special_file(value->path, ec_mem_cache_get_size_generic(value->path));
        value->fs_magic = fs_magic;
        atomic64_set(&value->reference_count, 1);

        TRACE(DL_FILE, "[%llu:%llu] %s was added to path cache.",
            value->key.device,
            value->key.inode,
            value->path);

        if (ec_hashtbl_add_generic_safe(s_file_cache, value, context) < 0)
        {
            // If the insert failed we free the local reference and get the existing value for the return
            ec_hashtbl_free_generic(s_file_cache, value, context);
            value = ec_path_cache_find(ns_id, device, inode, context);
        }
    }

    // Return the reference
    return value;
}

void ec_path_cache_delete(
    PathData           *value,
    ProcessContext     *context)
{
    CANCEL_VOID(value);

    ec_hashtbl_del_generic(s_file_cache, value, context);

    TRACE(DL_FILE, "[%llu:%llu] %s was removed from path cache.",
            value->key.device,
            value->key.inode,
            value->path);
}

void ec_path_cache_put(
    PathData           *path_data,
    ProcessContext     *context)
{
    ec_hashtbl_put_generic(s_file_cache, path_data, context);
}

void __ec_path_cache_delete_callback(void *data, ProcessContext *context)
{
    if (data)
    {
        PathData *value = (PathData *)data;

        ec_mem_cache_put_generic(value->path);
        value->path = NULL;
    }
}

int __ec_path_cache_print(HashTbl * hashTblp, HashTableNode * nodep, void *priv, ProcessContext *context);

int ec_path_cache_show(struct seq_file *m, void *v)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    ec_hashtbl_read_for_each_generic(s_file_cache, __ec_path_cache_print, m, &context);

CATCH_DISABLED:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return 0;
}

int __ec_path_cache_print(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context)
{
    PathData *datap = (PathData *)nodep;
    struct seq_file *m = priv;

    if (datap)
    {
        seq_printf(m, "FILE-CACHE [%llu:%llu] %s\n",
                   datap->key.device,
                   datap->key.inode,
                   datap->path);
    }

    return ACTION_CONTINUE;
}
