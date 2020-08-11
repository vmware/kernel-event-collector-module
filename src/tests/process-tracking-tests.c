/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#include "process-tracking.h"
#include "run-tests.h"

// NOTE: On kernel 3.10 and up this test produces a WARN because we don't
// expect this scenario to happen, but it's worth exercising the code path to
// check that the code handles the failure path in case somehow we do hit it.
// With the pre-3.10 exit hook it's possible to see a multiple exit event for the
// same pid. We warn on 3.10 because we don't expect to see this scenario.
// This test verifies:
//      - process_tracking_report_exit handling of active_process_count < 0
//      - on 2.32 the extra exit event is ignored
//      - on 3.10 a warning is issued
bool __init test__proc_track_report_double_exit(ProcessContext *context)
{
    bool passed = false;

    ProcessTracking *procp = process_tracking_create_process(
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

    ASSERT_TRY(procp);

    atomic64_set(&procp->shared_data->active_process_count, 0);
    ASSERT_TRY(!process_tracking_report_exit(200, context));
    ASSERT_TRY(atomic64_read(&procp->shared_data->exit_event) == 0);

    passed = true;
CATCH_DEFAULT:
    if (procp)
    {
        process_tracking_remove_process(procp, context);
        process_tracking_put_process(procp, context);
    }

    return passed;
}
