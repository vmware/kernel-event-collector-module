/* Copyright 2022 VMWare, Inc.  All rights reserved. */

#include "path-buffers.h"

#include "run-tests.h"

struct file *__ec_get_file_from_mm(struct mm_struct *mm);

bool __init test__task_get_path_data__use_comm(ProcessContext *context);

bool __init test__paths(ProcessContext *context)
{
    DECLARE_TEST();

    RUN_TEST(test__task_get_path_data__use_comm(context));

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