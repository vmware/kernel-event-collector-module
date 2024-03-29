/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#include "cb-spinlock.h"
#include "run-tests.h"

extern bool g_enable_hook_tracking;

int __ec_DoAction(ProcessContext *context, CB_EVENT_ACTION_TYPE action);

bool __init test__begin_finish_macros(ProcessContext *context);
bool __init test__hook_tracking_add_del(ProcessContext *context);
bool __init test__action_from_module_state(ModuleState current_state, CB_EVENT_ACTION_TYPE action, int expected_rc, ProcessContext *context);


bool __init test__module_state(ProcessContext *context)
{
    DECLARE_TEST();

    RUN_TEST(test__begin_finish_macros(context));
    RUN_TEST(test__hook_tracking_add_del(context));

    // These tests check return code from invalid or noop enable/disable requests
    RUN_TEST(test__action_from_module_state(ModuleStateDisabling, CB_EVENT_ACTION_ENABLE_EVENT_COLLECTOR, -EPERM, context));
    RUN_TEST(test__action_from_module_state(ModuleStateEnabling, CB_EVENT_ACTION_ENABLE_EVENT_COLLECTOR, -EPERM, context));
    RUN_TEST(test__action_from_module_state(ModuleStateEnabled, CB_EVENT_ACTION_ENABLE_EVENT_COLLECTOR, 0, context));
    RUN_TEST(test__action_from_module_state(ModuleStateDisabling, CB_EVENT_ACTION_DISABLE_EVENT_COLLECTOR, -EPERM, context));
    RUN_TEST(test__action_from_module_state(ModuleStateEnabling, CB_EVENT_ACTION_DISABLE_EVENT_COLLECTOR, -EPERM, context));
    RUN_TEST(test__action_from_module_state(ModuleStateDisabled, CB_EVENT_ACTION_DISABLE_EVENT_COLLECTOR, 0, context));

    RETURN_RESULT();
}

// This verifies multiple BEGIN/FINISH disable check macros in the same
// hook function. See ec_sys_rename for an example.
bool __init test__begin_finish_macros(ProcessContext *context)
{
    bool passed = false;
    unsigned int cpu;

    ModuleState module_state = g_module_state_info.module_state;

    // Initially we're enabled...
    g_module_state_info.module_state = ModuleStateEnabled;

    // so we enter the enabled-only section
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DISABLED);

    // Module enabled section //

    FINISH_MODULE_DISABLE_CHECK(context);

    // The module disables while we're outside the enabled-only section
    g_module_state_info.module_state = ModuleStateDisabling;

    // Now we try to enter an enabled-only section
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DISABLED);

    // Module enabled section //

    // We should never get here because the module is disabled
    ASSERT_TRY(false);

CATCH_DISABLED:
    // This will warn if the active call count is wrong
    FINISH_MODULE_DISABLE_CHECK(context);

    for_each_possible_cpu(cpu)
    {
        ASSERT_TRY(per_cpu(module_active_inuse, cpu) == 0);
    }
    passed = true;

CATCH_DEFAULT:
    // Set state back to original
    g_module_state_info.module_state = module_state;

    return passed;
}

bool __init test__hook_tracking_add_del(ProcessContext *context)
{
    bool passed = false;
    pid_t current_pid = ec_getpid(current);
    bool orig_hook_tracking = g_enable_hook_tracking;
    // ignore the passed in context for this test
    DECLARE_NON_ATOMIC_CONTEXT(test_context, current_pid);

    g_enable_hook_tracking = true;

    ASSERT_TRY(atomic64_read(&test_context.hook_tracking.count) == 0);

    ec_hook_tracking_add_entry(&test_context, __func__);

    ASSERT_TRY(atomic64_read(&test_context.hook_tracking.count) == 1);
    ASSERT_TRY(test_context.hook_tracking.last_pid == current_pid);

    // This is here to exercise this code since there's no easy way to force it to run.
    ec_hook_tracking_print_active(&test_context);

    ec_hook_tracking_del_entry(&test_context);

    ASSERT_TRY(atomic64_read(&test_context.hook_tracking.count) == 0);

    passed = true;

CATCH_DEFAULT:
    g_enable_hook_tracking = orig_hook_tracking;

    return passed;
}

bool __init test__action_from_module_state(ModuleState current_state, CB_EVENT_ACTION_TYPE action, int expected_rc, ProcessContext *context)
{
    bool passed = false;
    int rc;
    ModuleState module_state = g_module_state_info.module_state;

    g_module_state_info.module_state = current_state;

    rc = __ec_DoAction(context, action);

    ASSERT_TRY_MSG(rc == expected_rc, "rc: %d", rc);

    passed = true;

CATCH_DEFAULT:
    g_module_state_info.module_state = module_state;

    return passed;
}

