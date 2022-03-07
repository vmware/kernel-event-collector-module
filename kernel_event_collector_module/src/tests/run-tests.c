// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "run-tests.h"

bool __init run_tests(ProcessContext *context)
{
    bool all_passed = true;

    uint32_t origTraceLevel = g_traceLevel;
    g_traceLevel |= (uint32_t)DL_INFO;

    pr_alert("Running self-tests\n");

    RUN_TEST(test__mem_cache(context));
    RUN_TEST(test__hash_table(context));
    RUN_TEST(test__proc_tracking(context));
    RUN_TEST(test__module_state(context));
    RUN_TEST(test__comms(context));
    RUN_TEST(test__paths(context));

    g_traceLevel = origTraceLevel;

    // I do not want to load the module
    return false;
}
