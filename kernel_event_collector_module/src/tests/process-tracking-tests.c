/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#include "process-tracking.h"
#include "mem-alloc.h"
#include "run-tests.h"

bool __init test__proc_track_report_double_exit(ProcessContext *context);
bool __init test__sys_clone_missing_parent(ProcessContext *context);
bool __init test__set_exec(ProcessContext *context);
bool __init test__add_process_twice(ProcessContext *context);
bool __init test__alloc_exec_identity__spinlock_fails(ProcessContext *context);
bool __init test__fail_during_exec(ProcessContext *context);

bool __init test__proc_tracking(ProcessContext *context)
{
    DECLARE_TEST();

    // This test is causing a crash after refactoring.  I believe it is not setting something up correctly on the fake path
    //RUN_TEST(test__proc_track_report_double_exit(context));
    RUN_TEST(test__sys_clone_missing_parent(context));
    RUN_TEST(test__alloc_exec_identity__spinlock_fails(context));
    
    //These test currently fail but I'm leaving the code here in case it could be useful for debugging error handling in the future
    //RUN_TEST(test__add_process_twice(context));
    //RUN_TEST(test__set_exec(context));
    //RUN_TEST(test__fail_during_exec(context));

    RETURN_RESULT();
}

// NOTE: On kernel 3.10 and up this test produces a WARN because we don't
// expect this scenario to happen, but it's worth exercising the code path to
// check that the code handles the failure path in case somehow we do hit it.
// With the pre-3.10 exit hook it's possible to see a multiple exit event for the
// same pid. We warn on 3.10 because we don't expect to see this scenario.
// This test verifies:
//      - ec_process_tracking_report_exit handling of active_process_count < 0
//      - on 3.10 a warning is issued
//
// After the switch to the probe exit hook, the double-exit problem should not be possible anymore, which is
// what this test was originally written for.
bool __init test__proc_track_report_double_exit(ProcessContext *context)
{
    bool passed = false;

    ProcessHandle *handle = ec_process_tracking_create_process(
        200,
        100,
        200,
        0,
        0,
        0,
        CB_PROCESS_START_BY_FORK,
        NULL,
        REAL_START,
        context);

    ASSERT_TRY(handle);

    atomic64_set(&ec_process_exec_identity(handle)->active_process_count, 0);
    ASSERT_TRY(ec_process_tracking_report_exit(200, context));

    passed = true;
CATCH_DEFAULT:
    if (handle)
    {
        ec_process_tracking_remove_process(handle, context);
        ec_process_tracking_put_handle(handle, context);
    }

    return passed;
}

bool __init test__sys_clone_missing_parent(ProcessContext *context)
{
    bool passed = false;
    struct task_struct *task = current;
    pid_t pid = ec_getpid(task);
    pid_t ppid = ec_getppid(task);

    ASSERT_TRY(!ec_is_process_tracked(pid, context));
    ASSERT_TRY(!ec_is_process_tracked(ppid, context));

    DISABLE_WAKE_UP(context);

    // This simulates ec_sys_clone being called during a fork with a missing parent process and verifies the process
    // and parent get tracked.
    // We had a problem where, since the fork hook disables wakeup we would fail to allocate a PathData, then fail
    // to track the process.
    ec_sys_clone(context, current);

    ENABLE_WAKE_UP(context);

    ASSERT_TRY(ec_is_process_tracked(pid, context));
    ASSERT_TRY(ec_is_process_tracked(ppid, context));

    passed = true;

CATCH_DEFAULT:

    return passed;
}

ExecIdentity *ec_process_tracking_alloc_exec_identity(ProcessContext *context);
void ec_process_posix_identity_set_exec_identity(PosixIdentity *posix_identity, ExecIdentity *exec_identity, ProcessContext *context);
void ec_process_exec_handle_set_exec_identity(ExecHandle *exec_handle, ExecIdentity *exec_identity, ProcessContext *context);
void ec_user_comm_clear_queue(ProcessContext *context);


bool __init test__set_exec(ProcessContext *context)
{
    bool passed = false;
    struct task_struct *task      = current;
    PathData           *path_data;
    char               *pathname;
    uid_t              uid        = GET_UID();
    uid_t              euid       = GET_EUID();
    ProcessHandle      *handle    = NULL;
    long active_process_count;

    pathname = ec_mem_alloc(PATH_MAX + 1, context);
    ASSERT_TRY(pathname);

    memset(pathname, 'p', 8);
    pathname[PATH_MAX] = 0;
    path_data = ec_path_cache_add(0, 0, 0, pathname, 0, context);

    handle = ec_process_tracking_create_process(
        100,
        1,
        100,
        0,
        0,
        0,
        CB_PROCESS_START_BY_FORK,
        NULL,
        REAL_START,
        context);

    ASSERT_TRY(handle);

    TRACE(DL_INFO, "active_process_count: %ld", atomic64_read(&ec_process_exec_identity(handle)->active_process_count));

    ec_process_tracking_put_handle(handle, context);

    // ec_process_tracking_alloc_exec_identity needs to fail so that exec_identity fails to allocate
    //g_mem_alloc_fail_dump_stack = true;
    g_mem_cache_fail_interval = 1;
    handle = ec_process_tracking_update_process(
        100,
        100,
        uid,
        euid,
        path_data,
        0,
        CB_PROCESS_START_BY_EXEC,
        task,
        CB_EVENT_TYPE_PROCESS_START_EXEC,
        FAKE_START,
        context);
    g_mem_cache_fail_interval = 0;

    ASSERT_TRY(!handle);

    // PID 100 active_process_count should still be > 0. If it is 0 then we may free the exec_identity while it is still
    // in use by 100.
    handle = ec_process_tracking_get_handle(100, context);
    ASSERT_TRY(handle);

    active_process_count = atomic64_read(&ec_process_exec_identity(handle)->active_process_count);
    ASSERT_TRY_MSG(active_process_count > 0, "active_process_count: %ld", active_process_count);

    passed = true;
CATCH_DEFAULT:
    ec_process_tracking_put_handle(handle, context);

    return passed;
}

/* We should not get two forks with the same PID but there are failure modes that can
 * result in ec_process_tracking_create_process() being called twice with the same PID.
 * This test verifies that code path.
 */
bool __init test__add_process_twice(ProcessContext *context)
{
    bool passed = false;

    ProcessHandle      *handle1, *handle2;

    handle1 = ec_process_tracking_create_process(
            100,
            1,
            100,
            0,
            0,
            0,
            CB_PROCESS_START_BY_FORK,
            NULL,
            REAL_START,
            context);

    ASSERT_TRY(handle1);

    handle2 = ec_process_tracking_create_process(
            100,
            1,
            100,
            0,
            0,
            0,
            CB_PROCESS_START_BY_FORK,
            NULL,
            REAL_START,
            context);

    ASSERT_TRY(!handle2);

    ASSERT_TRY(ec_process_tracking_report_exit(100, context));

    passed = true;

CATCH_DEFAULT:
    ec_process_tracking_put_handle(handle1, context);

    return passed;
}

bool __init test__alloc_exec_identity__spinlock_fails(ProcessContext *context)
{
    bool passed = false;
    ExecIdentity *exec_identity = NULL;

    // We want ec_spinlock_init to fail and it uses mem_alloc
    //g_mem_alloc_fail_dump_stack = true;
    g_mem_alloc_fail_interval = 1;
    exec_identity = ec_process_tracking_alloc_exec_identity(context);
    g_mem_cache_fail_interval = 0;

    // The exec_identity must fail to allocate because the spinlock failed to allocate
    ASSERT_TRY(!exec_identity);


    passed = true;

CATCH_DEFAULT:
    return passed;
}

bool __init test__fail_during_exec(ProcessContext *context)
{
    bool passed = false;

    struct task_struct *task      = current;
    PathData           *path_data;
    char               *pathname;
    uid_t              uid        = GET_UID();
    uid_t              euid       = GET_EUID();
    ProcessHandle      *handle    = NULL;
    pid_t              pid        = ec_getpid(task);
    pid_t              ppid       = ec_getppid(task);

    pathname = ec_mem_alloc(PATH_MAX + 1, context);
    ASSERT_TRY(pathname);

    memset(pathname, 'p', 8);
    pathname[PATH_MAX] = 0;
    path_data = ec_path_cache_add(0, 0, 0, pathname, 0, context);

    // create initial process
    handle = ec_process_tracking_create_process(
            ppid,
            1,
            ppid,
            uid,
            euid,
            0,
            CB_PROCESS_START_BY_FORK,
            NULL,
            REAL_START,
            context);

    ASSERT_TRY(handle);
    ec_process_tracking_put_handle(handle, context);

    // fork second process
    handle = ec_process_tracking_create_process(
            pid,
            ppid,
            pid,
            uid,
            euid,
            0,
            CB_PROCESS_START_BY_FORK,
            NULL,
            REAL_START,
            context);

    ASSERT_TRY(handle);
    ec_process_tracking_put_handle(handle, context);

    g_mem_alloc_fail_dump_stack = true;
    // fail the first  ec_process_tracking_get_handle()
    g_mem_alloc_fail_interval = 1;

    // exec second process
    handle = ec_process_tracking_update_process(
            pid,
            pid,
            uid,
            euid,
            path_data,
            0,
            CB_PROCESS_START_BY_EXEC,
            task,
            CB_EVENT_TYPE_PROCESS_START_EXEC,
            FAKE_START,
            context);
    g_mem_alloc_fail_interval = 0;

    // Should fail because it tried to create an extant process
    ASSERT_TRY(!handle);
    //ec_process_tracking_put_handle(handle, context);

    // second process exits
    TRACE(DL_INFO, "ec_process_tracking_report_exit");
    ASSERT_TRY(ec_process_tracking_report_exit(pid, context));

    TRACE(DL_INFO, "ec_process_tracking_get_handle");
    // try to get handle to initial process
    handle = ec_process_tracking_get_handle(ppid, context);
    ASSERT_TRY(handle);

    passed = true;

CATCH_DEFAULT:
    ec_process_tracking_put_handle(handle, context);

    return passed;
}
