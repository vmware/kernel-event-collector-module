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

uint32_t g_file_path_buckets = 65536*2;

void __ec_path_cache_delete_callback(void *data, ProcessContext *context);
int __ec_path_cache_print(HashTbl *hashTblp, void *datap, void *priv, ProcessContext *context);
void __ec_path_cache_print_callback(void *datap, ProcessContext *context);
bool __ec_path_cache_verify_callback(void *datap, void *key, ProcessContext *context);
void __ec_path_cache_print_ref(int log_level, const char *calling_func, PathData *path_data, ProcessContext *context);

static HashTbl __read_mostly s_path_cache = {
    .name = "file_path_cache",
    .datasize = sizeof(PathData),
    .key_len     = sizeof(PathKey),
    .key_offset  = offsetof(PathData, key),
    .refcount_offset = offsetof(PathData, reference_count),
    .delete_callback = __ec_path_cache_delete_callback,
    .printval_callback = __ec_path_cache_print_callback,
    .find_verify_callback = __ec_path_cache_verify_callback,
};

bool ec_path_cache_init(ProcessContext *context)
{
    s_path_cache.numberOfBuckets = g_file_path_buckets;
    return ec_hashtbl_init(&s_path_cache, context);
}

void ec_path_cache_shutdown(ProcessContext *context)
{
    ec_hashtbl_destroy(&s_path_cache, context);
}

PathData *ec_path_cache_find(
    PathQuery          *query,
    ProcessContext     *context)
{
    CANCEL(likely(query), NULL);
    return ec_hashtbl_find(&s_path_cache, &query->key, context);
}

bool __ec_path_cache_verify_callback(void *datap, void *keyp, ProcessContext *context)
{
    PathData *path_data = (PathData *)datap;
    PathQuery *verify = container_of(keyp, PathQuery, key);

    CANCEL(likely(datap && keyp), false);

    if (verify->ignore_special)
    {
        verify->path_ignored = path_data->is_special_file;
        return !path_data->is_special_file;
    }

    return true;
}

PathData *ec_path_cache_get(
    PathData           *path_data,
    ProcessContext     *context)
{
    path_data = ec_hashtbl_get(&s_path_cache, path_data, context);

    __ec_path_cache_print_ref(DL_FILE, __func__, path_data, context);

    return path_data;
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
            PathQuery query = {
                .key = { ns_id, device, inode },
            };

            // If the insert failed we free the local reference and get the existing value for the return
            __ec_path_cache_print_ref(DL_FILE, __func__, value, context);
            ec_hashtbl_free(&s_path_cache, value, context);
            value = ec_path_cache_find(&query, context);
        }
        __ec_path_cache_print_ref(DL_FILE, __func__, value, context);
    }

    // Return the reference
    return value;
}

void ec_path_cache_delete(
    PathData           *value,
    ProcessContext     *context)
{
    CANCEL_VOID(value);

    __ec_path_cache_print_ref(DL_FILE, __func__, value, context);
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
    __ec_path_cache_print_ref(DL_FILE, __func__, path_data, context);

    ec_hashtbl_put(&s_path_cache, path_data, context);
}

void __ec_path_cache_delete_callback(void *data, ProcessContext *context)
{
    if (data)
    {
        PathData *value = (PathData *)data;

        __ec_path_cache_print_ref(DL_FILE, __func__, value, context);
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
        seq_printf(m, "PATH-CACHE [%llu:%llu] %s\n",
                   path_data->key.device,
                   path_data->key.inode,
                   path_data->path);
    }

    return ACTION_CONTINUE;
}

void __ec_path_cache_print_callback(void *datap, ProcessContext *context)
{
    PathData *path_data = (PathData *)datap;

    if (datap)
    {
        TRACE(DL_ERROR, "    PATH-CACHE [%llu:%llu] %s (ref: %lld) (%p)",
                   path_data->key.device,
                   path_data->key.inode,
                   path_data->path,
                   ec_hashtbl_ref_count(&s_path_cache, datap, context),
                   path_data);
        __ec_path_cache_print_ref(DL_FILE, __func__, path_data, context);
    }
}

void __ec_path_cache_print_ref(int log_level, const char *calling_func, PathData *path_data, ProcessContext *context)
{
    char *ref_str = NULL;

    CANCEL_VOID(g_path_cache_ref_debug);
    CANCEL_VOID(path_data);
    CANCEL_VOID(MAY_TRACE_LEVEL(log_level));

    ref_str = ec_mem_alloc(20, context);
    CANCEL_VOID(ref_str);

    TRACE(log_level, "    %s: [%llu:%llu] %s (ref: %lld) [%s] (%p)",
          calling_func,
          path_data->key.device,
          path_data->key.inode,
          path_data->path,
          ec_hashtbl_ref_count(&s_path_cache, path_data, context),
          ref_str,
          path_data);

    ec_mem_free(ref_str);
}
