/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#pragma once

#include <linux/init.h>

#include "process-context.h"
#include "priv.h"

//
// run_tests provides a way to write consumption tests that exercise and verify
// components of the kernel module. These tests may crash the kernel and should
// not be run in production environments.
//
// To run self-tests include the g_run_self_tests arg when loading the module:
//   insmod event_collector_2_0_999999.ko.3.10.0-957 g_run_self_tests
//
// Test functions and global data must use the __init decorator. This allows
// the kernel to unload these functions and data after initialization.
//
#define DECLARE_TEST() bool all_passed = true
#define RETURN_RESULT() return all_passed
#define RUN_TEST(test_stmt) do {\
    TRACE(DL_INFO, "%s START", #test_stmt); \
    if (test_stmt) { \
        TRACE(DL_INFO, "%s PASSED", #test_stmt); \
    } else { \
        TRACE(DL_INFO, "%s FAILED", #test_stmt); \
        all_passed = false; \
    } \
} while (0);

bool __init run_tests(ProcessContext *context);

bool __init test__mem_cache(ProcessContext *context);
bool __init test__hash_table(ProcessContext *context);
bool __init test__proc_tracking(ProcessContext *context);
bool __init test__module_state(ProcessContext *context);
bool __init test__comms(ProcessContext *context);
bool __init test__paths(ProcessContext *context);

#define ASSERT_TRY(stmt)  TRY_MSG(stmt, DL_ERROR, "ASSERT FAILED: [%s:%d] %s", __FILE__, __LINE__, #stmt)
#define ASSERT_TEST(stmt) R_TEST(stmt, { TRACE(DL_ERROR, "ASSERT FAILED: [%s:%d] %s", __FILE__, __LINE__, #stmt); }, { passed = false; } );
#define ASSERT_TRY_MSG(stmt, msg, ...) TRY_MSG(stmt, DL_ERROR, "ASSERT FAILED [%s:%d] -- " msg, __FILE__, __LINE__, ##__VA_ARGS__)
