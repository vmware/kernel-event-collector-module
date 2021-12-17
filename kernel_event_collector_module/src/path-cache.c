// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 VMware Inc.  All rights reserved.

#include "hash-table.h"
#include "path-cache.h"
#include "file-helper.h"
#include "module_state.h"
#include "task-helper.h"
#include "cb-test.h"
#include "priv.h"
#include "mem-alloc.h"

void __ec_path_cache_delete_callback(void *data, ProcessContext *context);
int __ec_path_cache_print(HashTbl *hashTblp, void *datap, void *priv, ProcessContext *context);

static HashTbl __read_mostly s_path_cache = {
    .numberOfBuckets = 1024,
    .name = "file_path_cache",
    .datasize = sizeof(PathData),
    .key_len     = sizeof(PathKey),
    .key_offset  = offsetof(PathData, key),
    .refcount_offset = offsetof(PathData, reference_count),
    .delete_callback = __ec_path_cache_delete_callback,
};


bool ec_path_cache_init(ProcessContext *context)
{
    return ec_hashtbl_init(&s_path_cache, context);
}

void ec_path_cache_shutdown(ProcessContext *context)
{
    ec_hashtbl_destroy(&s_path_cache, context);
}

PathData *ec_path_cache_find(
    uint64_t            ns_id,
    uint64_t            device,
    uint64_t            inode,
    ProcessContext     *context)
{
    PathKey key = { ns_id, device, inode };

    return ec_hashtbl_find(&s_path_cache, &key, context);
}


PathData *ec_path_cache_get(
    PathData           *path_data,
    ProcessContext     *context)
{
    return ec_hashtbl_get(&s_path_cache, path_data, context);
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
        value = ec_hashtbl_alloc(&s_path_cache, context);
        CANCEL(value, NULL);

        value->key.ns_id = ns_id;
        value->key.device = device;
        value->key.inode = inode;
        value->path = ec_mem_get(path, context);
        value->path_found = !!path; // It is possible that the path will be NULL now but set later
        value->file_id = ec_get_current_time(); // Use this as a unique ID
        value->is_special_file = ec_is_special_file(value->path, ec_mem_size(value->path));
        value->fs_magic = fs_magic;
        atomic64_set(&value->reference_count, 1);

        TRACE(DL_FILE, "[%llu:%llu] %s was added to path cache.",
            value->key.device,
            value->key.inode,
            value->path);

        if (ec_hashtbl_add_safe(&s_path_cache, value, context) < 0)
        {
            // If the insert failed we free the local reference and get the existing value for the return
            ec_hashtbl_free(&s_path_cache, value, context);
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

    ec_hashtbl_del(&s_path_cache, value, context);

    TRACE(DL_FILE, "[%llu:%llu] %s was removed from path cache.",
            value->key.device,
            value->key.inode,
            value->path);
}

void ec_path_cache_put(
    PathData           *path_data,
    ProcessContext     *context)
{
    ec_hashtbl_put(&s_path_cache, path_data, context);
}

void __ec_path_cache_delete_callback(void *data, ProcessContext *context)
{
    if (data)
    {
        PathData *value = (PathData *)data;

        ec_mem_put(value->path);
        value->path = NULL;
    }
}

int ec_path_cache_show(struct seq_file *m, void *v)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    ec_hashtbl_read_for_each(&s_path_cache, __ec_path_cache_print, m, &context);

CATCH_DISABLED:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return 0;
}

int __ec_path_cache_print(HashTbl *hashTblp, void *datap, void *priv, ProcessContext *context)
{
    PathData *path_data = (PathData *)datap;
    struct seq_file *m = priv;

    if (datap)
    {
        seq_printf(m, "FILE-CACHE [%llu:%llu] %s\n",
                   path_data->key.device,
                   path_data->key.inode,
                   path_data->path);
    }

    return ACTION_CONTINUE;
}
