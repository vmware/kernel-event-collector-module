// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "file-process-tracking.h"
#include "process-tracking.h"
#include "hash-table-generic.h"
#include "priv.h"
#include "rbtree-helper.h"

static int _file_process_tree_compare(void *left, void *right);
static void _file_process_tree_free(void *data, ProcessContext *context);
static void _file_process_tree_copy(void *dest, void *src);

static CB_MEM_CACHE s_file_process_cache;

static FILE_PROCESS_VALUE *file_process_alloc(ProcessContext *context);


bool file_process_tracking_init(ProcessContext *context)
{
    return cb_mem_cache_create(&s_file_process_cache, "file_process_cache", sizeof(FILE_PROCESS_VALUE), context);
}

void file_process_tracking_shutdown(ProcessContext *context)
{
    cb_mem_cache_destroy(&s_file_process_cache, context, NULL);
}

static FILE_PROCESS_VALUE *file_process_alloc(ProcessContext *context)
{
    FILE_PROCESS_VALUE *value = (FILE_PROCESS_VALUE *)cb_mem_cache_alloc(&s_file_process_cache, context);

    if (value)
    {
        RB_CLEAR_NODE(&value->node);
        value->path = NULL;
    }

    return value;
}

static void file_process_free(FILE_PROCESS_VALUE *value, ProcessContext *context)
{
    if (value)
    {
        if (value->path)
        {
            cb_mem_cache_free_generic(value->path);
            value->path = NULL;
        }
        cb_mem_cache_free(&s_file_process_cache, value, context);
    }
}


FILE_PROCESS_VALUE *file_process_status_open(
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
    const char *process_path = "<unknown>";

    TRY(process_tracking_get_file_tree(pid, &tree_handle, context));

    value = cb_rbtree_search(tree_handle.tree, &key, context);
    if (!value)
    {
        value = file_process_alloc(context);
        TRY(value);

        value->key.device    = device;
        value->key.inode     = inode;
        value->pid           = pid;
        value->isSpecialFile = isSpecialFile;
        value->fileType      = filetypeUnknown;
        value->didReadType   = false;
        value->status = OPENED;

        if (path && *path)
        {
            size_t len = strlen(path);

            value->path = cb_mem_cache_alloc_generic(len + 1, context);
            if (value->path)
            {
                value->path[0] = 0;
                strncat(value->path, path, len);
            }
        }

        if (!cb_rbtree_insert(tree_handle.tree, value, context))
        {
            // Will also free path
            file_process_free(value, context);
            value = NULL;
            if (tree_handle.shared_data)
            {
                process_path = process_tracking_get_path(tree_handle.shared_data);
            }

            // We are racing against other threads or processes
            // to insert a similar entry on the same rb_tree.
            TRACE(DL_INFO, "File entry already exists: [%llu:%llu] %s pid:%u (%s)",
                device, inode, path ? path : "(path unknown)", pid, process_path);
        }
    }

CATCH_DEFAULT:
    process_tracking_put_file_tree(&tree_handle, context);

    return value;
}

FILE_PROCESS_VALUE *file_process_status(uint64_t device, uint64_t inode, uint32_t pid, ProcessContext *context)
{
    FILE_PROCESS_VALUE *value = NULL;
    FILE_TREE_HANDLE tree_handle;
    FILE_PROCESS_KEY key = {device, inode};

    TRY(process_tracking_get_file_tree(pid, &tree_handle, context));

    value = cb_rbtree_search(tree_handle.tree, &key, context);

CATCH_DEFAULT:
    process_tracking_put_file_tree(&tree_handle, context);

    return value;
}

bool file_process_status_update(uint64_t device, uint64_t inode, uint32_t pid, FILE_PROCESS_VALUE *processValue, ProcessContext *context)
{
    FILE_TREE_HANDLE tree_handle;
    FILE_PROCESS_KEY key = {device, inode};
    bool updated = false;

    TRY(process_tracking_get_file_tree(pid, &tree_handle, context));

    updated = cb_rbtree_update(tree_handle.tree, &key, processValue, context);

CATCH_DEFAULT:
    process_tracking_put_file_tree(&tree_handle, context);

    return updated;
}

void file_process_status_close(uint64_t device, uint64_t inode, uint32_t pid, ProcessContext *context)
{
    FILE_TREE_HANDLE tree_handle;
    FILE_PROCESS_KEY key = {device, inode};

    CANCEL_VOID(process_tracking_get_file_tree(pid, &tree_handle, context));

    cb_rbtree_delete_by_key(tree_handle.tree, &key, context);

    process_tracking_put_file_tree(&tree_handle, context);
}

// When a process exits we want to go over the list of open files that it owns and
//  remove them.
void check_open_file_list_on_exit(CB_RBTREE *tree, ProcessContext *context)
{
    if (tree)
    {
         cb_rbtree_clear(tree, context);
    }
}

void file_process_tree_init(void **tree, ProcessContext *context)
{
    if (tree)
    {
        *tree = cb_mem_cache_alloc_generic(sizeof(CB_RBTREE), context);
        if (*tree)
        {
            cb_rbtree_init(*tree,
                           offsetof(FILE_PROCESS_VALUE, key),
                           offsetof(FILE_PROCESS_VALUE, node),
                           _file_process_tree_compare,
                           _file_process_tree_free,
                           _file_process_tree_copy,
                           context);
        }
    }
}

void file_process_tree_destroy(void **tree, ProcessContext *context)
{
    if (tree && *tree)
    {
        cb_rbtree_destroy(*tree, context);
        cb_mem_cache_free_generic(*tree);
        *tree = NULL;
    }
}

// This helper function is used by the rbtree to find nodes
static int _file_process_tree_compare(void *left, void *right)
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

static void _file_process_tree_copy(void *dest, void *src)
{
    FILE_PROCESS_VALUE *fp_dest = (FILE_PROCESS_VALUE *)dest;
    FILE_PROCESS_VALUE *fp_src = (FILE_PROCESS_VALUE *)src;

    // only updateable fields are copied
    fp_dest->fileType = fp_src->fileType;
    fp_dest->didReadType = fp_src->didReadType;
}

static void _file_process_tree_free(void *data, ProcessContext *context)
{
    file_process_free(data, context);
}

static void _for_each_file_tree(void *tree, void *priv, ProcessContext *context);
static void _show_file_tracking_table(void *data, void *priv, ProcessContext *context);
static char *getTypeStr(CB_FILE_TYPE type);

struct _tree_priv {
    struct seq_file *m;
    uint64_t         count;
};

int cb_file_track_show_table(struct seq_file *m, void *v)
{

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    seq_printf(m, "%40s | %10s | %10s | %6s | %10s | %15s | %10s |\n",
                   "Path", "Device", "Inode", "PID", "Is Special", "Type", "Count");

    process_tracking_for_each_file_tree(_for_each_file_tree, m, &context);

    return 0;
}

static void _for_each_file_tree(void *tree, void *priv, ProcessContext *context)
{
    if (tree)
    {
        struct _tree_priv tree_priv = {priv, atomic64_read(&((CB_RBTREE *)tree)->count)};

        cb_rbtree_read_for_each(tree, _show_file_tracking_table, &tree_priv, context);
    }
}

static void _show_file_tracking_table(void *data, void *priv, ProcessContext *context)
{
    if (data && priv)
    {
        FILE_PROCESS_VALUE *value = (FILE_PROCESS_VALUE *)data;
        struct _tree_priv *local_priv = (struct _tree_priv *)priv;

        seq_printf(local_priv->m, "%40s | %10llu | %10llu | %6d | %10s | %15s | %10llu |\n",
                      value->path,
                      value->key.device,
                      value->key.inode,
                      value->pid,
                      (value->isSpecialFile ? "YES" : "NO"),
                      getTypeStr(value->fileType),
                      local_priv->count);
    }
}

static char *getTypeStr(CB_FILE_TYPE type)
{
    char *str = "unknown";

    switch (type)
    {
    case filetypePe: str = "PE";              break;
    case filetypeElf: str = "ELF";             break;
    case filetypeUniversalBin: str = "Univ. Bin";       break;
    case filetypeEicar: str = "EICAR";           break;
    case filetypeOfficeLegacy: str = "Office Legacy";   break;
    case filetypeOfficeOpenXml: str = "Office Open XML"; break;
    case filetypePdf: str = "PDF";             break;
    case filetypeArchivePkzip: str = "PKZIP";           break;
    case filetypeArchiveLzh: str = "LZH";             break;
    case filetypeArchiveLzw: str = "LZW";             break;
    case filetypeArchiveRar: str = "RAR";             break;
    case filetypeArchiveTar: str = "TAR";             break;
    case filetypeArchive7zip: str = "7 ZIP";           break;
    case filetypeUnknown:
    default:                                                break;
    }
    return str;
}
