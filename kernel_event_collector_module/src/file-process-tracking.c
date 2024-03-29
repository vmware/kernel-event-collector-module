// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "hash-table.h"
#include "file-process-tracking.h"
#include "process-tracking.h"
#include "process-tracking-private.h"
#include "hash-table.h"
#include "priv.h"

uint32_t g_file_tracking_buckets = 65536;

void __ec_file_tracking_delete_callback(void *posix_identity, ProcessContext *context);
int __ec_file_tracking_show(HashTbl *hashTblp, void *datap, void *priv, ProcessContext *context);

static HashTbl __read_mostly s_file_hash_table = {
    .name = "file_tracking_table",
    .datasize = sizeof(FILE_PROCESS_VALUE),
    .key_len     = sizeof(FILE_PROCESS_KEY),
    .key_offset  = offsetof(FILE_PROCESS_VALUE, key),
    .delete_callback = __ec_file_tracking_delete_callback,
};

bool ec_file_tracking_init(ProcessContext *context)
{
    s_file_hash_table.numberOfBuckets = g_file_tracking_buckets;
    return ec_hashtbl_init(&s_file_hash_table, context);
}

void ec_file_tracking_shutdown(ProcessContext *context)
{
    ec_hashtbl_destroy(&s_file_hash_table, context);
}

void __ec_file_tracking_delete_callback(void *data, ProcessContext *context)
{
    if (data)
    {
        FILE_PROCESS_VALUE *value = (FILE_PROCESS_VALUE *)data;

        ec_path_cache_put(value->path_data, context);
        value->path_data = NULL;
    }
}


FILE_PROCESS_VALUE *ec_file_process_status_open(
    struct file    *file,
    uint32_t        pid,
    PathData       *path_data,
    ProcessContext *context)
{
    FILE_PROCESS_VALUE *value = ec_file_process_get(file, context);

    if (!value)
    {
        value = ec_hashtbl_alloc(&s_file_hash_table, context);
        TRY(value);

        value->key.file      = (uint64_t)file;
        value->pid           = pid;
        value->path_data     = ec_path_cache_get(path_data, context);

        if (ec_hashtbl_add(&s_file_hash_table, value, context) < 0)
        {
            if (MAY_TRACE_LEVEL(DL_FILE))
            {
                // We are racing against other threads or processes
                // to insert a similar entry on the same rb_tree.
                TRACE(DL_FILE, "File entry already exists: [%llu:%llu] %s pid:%u",
                      value->path_data->key.device,
                      value->path_data->key.inode,
                      SANE_PATH(value->path_data->path),
                      pid);
            }

            // If the insert failed we free the local reference and clear
            //  value
            ec_hashtbl_free(&s_file_hash_table, value, context);
            value = NULL;
        }
    }

CATCH_DEFAULT:
    // Return holding a reference
    return value;
}

FILE_PROCESS_VALUE *ec_file_process_get(
    struct file    *file,
    ProcessContext *context)
{
    FILE_PROCESS_KEY key = { (uint64_t)file };

    return ec_hashtbl_find(&s_file_hash_table, &key, context);
}

void ec_file_process_status_close(
    struct file    *file,
    ProcessContext *context)
{
    FILE_PROCESS_KEY key = {(uint64_t)file};
    FILE_PROCESS_VALUE *value = NULL;

    value = ec_hashtbl_del_by_key(&s_file_hash_table, &key, context);

    // We still need to release it
    ec_hashtbl_put(&s_file_hash_table, value, context);
}

void ec_file_process_put_ref(FILE_PROCESS_VALUE *value, ProcessContext *context)
{
    ec_hashtbl_put(&s_file_hash_table, value, context);
}

int ec_file_track_show_table(struct seq_file *m, void *v)
{

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    seq_printf(m, "%50s | %10s | %10s | %6s | %10s | %10s |\n",
                   "Path", "Device", "Inode", "PID", "Is Special", "File Pointer");

    ec_hashtbl_read_for_each(
        &s_file_hash_table,
        __ec_file_tracking_show,
        m,
        &context);

    return 0;
}

int __ec_file_tracking_show(HashTbl *hashTblp, void *datap, void *m, ProcessContext *context)
{
    if (datap && m)
    {
        FILE_PROCESS_VALUE *value = (FILE_PROCESS_VALUE *)datap;

        seq_printf(m, "%50s | %10llu | %10llu | %6d | %10s | %10llx |\n",
                      SANE_PATH(value->path_data->path),
                      value->path_data->key.device,
                      value->path_data->key.inode,
                      value->pid,
                      value->path_data->is_special_file ? "YES" : "NO",
                      value->key.file);
    }

    return ACTION_CONTINUE;
}
