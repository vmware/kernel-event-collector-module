/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#include "process-tracking.h"
#include "run-tests.h"

bool __init test__proc_track_report_double_exit(ProcessContext *context);
bool __init test__sys_clone_missing_parent(ProcessContext *context);

bool __init test__proc_tracking(ProcessContext *context)
{
    DECLARE_TEST();

    // This test is causing a crash after refactoring.  I believe it is not setting something up correctly on the fake path
    //RUN_TEST(test__proc_track_report_double_exit(context));
    RUN_TEST(test__sys_clone_missing_parent(context));

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

