// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "run-tests.h"

bool __init run_tests(ProcessContext *context)
{
    DECLARE_TEST();

    uint32_t origTraceLevel = g_traceLevel;
    g_traceLevel |= (uint32_t)DL_INFO;

    TRACE(DL_INFO, "Running self-tests");

    RUN_TEST(test__mem_cache(context));
    RUN_TEST(test__hash_table(context));
    RUN_TEST(test__proc_tracking(context));
    RUN_TEST(test__module_state(context));
    RUN_TEST(test__comms(context));
    RUN_TEST(test__paths(context));

    TRACE(DL_ERROR, "Self-tests done, %d failures", test_failures);

    g_traceLevel = origTraceLevel;

    // I do not want to load the module
    return false;
}
