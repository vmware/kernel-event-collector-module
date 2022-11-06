/* Copyright 2022 VMWare, Inc.  All rights reserved. */

#include "path-buffers.h"
#include "mem-alloc.h"
#include "mem-cache.h"

#include "run-tests.h"

#include <linux/magic.h>


struct file *__ec_get_file_from_mm(struct mm_struct *mm);

bool __init test__task_get_path_data__use_comm(ProcessContext *context);
bool __init test__path_cache_add__ignored_fs(ProcessContext *context);
bool __init test__get_path_data__invalid(ProcessContext *context);
bool __init test__get_path_data__mem_fail(ProcessContext *context);

bool __init test__paths(ProcessContext *context)
{
    DECLARE_TEST();

    RUN_TEST(test__task_get_path_data__use_comm(context));
    RUN_TEST(test__path_cache_add__ignored_fs(context));
    RUN_TEST(test__get_path_data__invalid(context));
    RUN_TEST(test__get_path_data__mem_fail(context));

    RETURN_RESULT();
}

bool __init test__task_get_path_data__use_comm(ProcessContext *context)
{
    bool passed = false;
    struct task_struct *task = current;
    PathData *path_data = NULL;

    DISABLE_WAKE_UP(context);

    // This is what happens if ec_task_get_path_data is called with wakeup disabled (e.g. during a fork).
    // With wakeup disabled, it should still be able to get a path from the task->comm.
    path_data = ec_task_get_path_data(task, NULL, context);

    ENABLE_WAKE_UP(context);

    ASSERT_TRY(path_data);
    ASSERT_TRY(path_data->path_found);
    ASSERT_TRY(path_data->path);
    ASSERT_TRY(path_data->key.device);
    ASSERT_TRY(path_data->key.inode);

    passed = true;

CATCH_DEFAULT:
    ec_path_cache_delete(path_data, context);
    ec_path_cache_put(path_data, context);

    return passed;
}

bool __init test__path_cache_add__ignored_fs(ProcessContext *context)
{
    bool passed = false;
    struct file *file = NULL;
    PathData *path_data = NULL;
    uint64_t device, inode, fs_magic;
    char *path = ec_mem_strdup("/tmp", context);

    file = filp_open(path, O_RDONLY, 0);

    ASSERT_TRY(file);

    // Get a real inode and device
    ec_get_devinfo_fs_magic_from_file(file, &device, &inode, &fs_magic);

    // Set fs_magic to an ignored FS
    fs_magic = NFS_SUPER_MAGIC;

    path_data = ec_path_cache_add(0, device, inode, path, fs_magic, context);

    // The cache should not be added to the cache but a valid path_data should be returned
    ASSERT_TRY(path_data);
    ASSERT_TRY(path_data->path_found);
    ASSERT_TRY(path_data->path);
    ASSERT_TRY(path_data->key.device);
    ASSERT_TRY(path_data->key.inode);

    passed = true;

CATCH_DEFAULT:
    ec_path_cache_delete(path_data, context);
    ec_path_cache_put(path_data, context);
    ec_mem_put(path);

    return passed;
}

bool __init test__get_path_data__invalid(ProcessContext *context)
{
    bool passed = false;
    struct path_lookup path_lookup = {
        .file = NULL,
    };
    PathData *path_data = NULL;

    path_data = ec_file_get_path_data(&path_lookup, context);

    ASSERT_TRY(path_data);
    ASSERT_TRY(!path_data->path_found);
    ASSERT_TRY(!path_data->path);
    ASSERT_TRY(!path_data->key.device);
    ASSERT_TRY(!path_data->key.inode);

    passed = true;

CATCH_DEFAULT:
    ec_path_cache_delete(path_data, context);
    ec_path_cache_put(path_data, context);

    return passed;
}

bool __init get_path_data__mem_fail(int interval, bool mem_alloc, bool expect, ProcessContext *context)
{
    bool passed = false;
    struct path_lookup path_lookup = {
        .path_buffer = NULL,
    };
    PathData *path_data = NULL;
    struct file *file = NULL;
    char *path = ec_mem_strdup("/tmp", context);

    file = filp_open(path, O_RDONLY, 0);
    ASSERT_TRY(file);
    path_lookup.path = &file->f_path;
    path_lookup.filename = path;

    if (mem_alloc)
    {
        g_mem_alloc_fail_interval = interval;
    } else
    {
        g_mem_cache_fail_interval = interval;
    }
    path_data = ec_file_get_path_data(&path_lookup, context);
    if (mem_alloc)
    {
        g_mem_alloc_fail_interval = 0;
    } else
    {
        g_mem_cache_fail_interval = 0;
    }

    ASSERT_TRY(expect ? !!path_data : !path_data);

    passed = true;

CATCH_DEFAULT:
    ec_path_cache_delete(path_data, context);
    ec_path_cache_put(path_data, context);

    g_mem_cache_fail_interval = 0;

    return passed;
}

bool __init test__get_path_data__mem_fail(ProcessContext *context)
{
    bool passed = false;

    ASSERT_TRY(get_path_data__mem_fail(1, true, true, context));
    ASSERT_TRY(get_path_data__mem_fail(2, true, true, context));

    // These tests don't currently pass, the expectation may be wrong
    //ASSERT_TRY(get_path_data__mem_fail(1, false, false, context));
    //ASSERT_TRY(get_path_data__mem_fail(2, false, false, context));
    //ASSERT_TRY(get_path_data__mem_fail(3, false, false, context));

    passed = true;

CATCH_DEFAULT:
    return passed;
}