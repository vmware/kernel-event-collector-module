/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#include "cb-spinlock.h"
#include "run-tests.h"

// This verifies multiple BEGIN/FINISH disable check macros in the same
// hook function. See cb_sys_rename for an example.
bool __init test__begin_finish_macros(ProcessContext *context)
{
    bool passed = false;

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

    ASSERT_TRY(atomic64_read(&g_module_state_info.module_active_call_count) == 0);
    passed = true;

CATCH_DEFAULT:
    // Make sure the state is set back to disabled
    g_module_state_info.module_state = ModuleStateDisabled;

    return passed;
}