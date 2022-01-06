// Copyright 2021 VMware Inc.  All rights reserved.

#include "run-tests.h"
#include "mem-cache.h"

bool __init test__mem_cache_create_destroy(ProcessContext *context);
bool __init test__mem_cache_alloc(ProcessContext *context);
bool __init test__mem_cache_get_put(ProcessContext *context);
bool __init test__mem_cache_delete_cb(ProcessContext *context);

bool __init test__mem_cache(ProcessContext *context)
{
    DECLARE_TEST();

    RUN_TEST(test__mem_cache_create_destroy(context));
    RUN_TEST(test__mem_cache_alloc(context));
    RUN_TEST(test__mem_cache_get_put(context));
    RUN_TEST(test__mem_cache_delete_cb(context));

    RETURN_RESULT();
}

bool __init test__mem_cache_create_destroy(ProcessContext *context)
{
    CB_MEM_CACHE mem_cache = CB_MEM_CACHE_INIT();

    ASSERT_TRY(ec_mem_cache_create(&mem_cache, "test cache", 50, context));
    ASSERT_TRY(ec_mem_cache_destroy(&mem_cache, context) == 0);

    return true;

CATCH_DEFAULT:
    return false;
}

bool __init test__mem_cache_alloc(ProcessContext *context)
{
    bool passed = true;
    CB_MEM_CACHE mem_cache = CB_MEM_CACHE_INIT();
    void *value = NULL;

    ASSERT_TRY(ec_mem_cache_create(&mem_cache, "test cache", 50, context));

    value = ec_mem_cache_alloc(&mem_cache, context);
    ASSERT_TEST(value != NULL);

    if (value)
    {
        ASSERT_TEST(ec_mem_cache_get_allocated_count(&mem_cache, context) == 1);
        ec_mem_cache_disown(value, context);
    }

    usleep_range(10000, 15000);
    ASSERT_TEST(ec_mem_cache_destroy(&mem_cache, context) == 0);


    return passed;

CATCH_DEFAULT:
    return false;
}

bool __init test__mem_cache_get_put(ProcessContext *context)
{
    bool passed = true;
    CB_MEM_CACHE mem_cache = CB_MEM_CACHE_INIT();
    void *value = NULL;

    ASSERT_TRY(ec_mem_cache_create(&mem_cache, "test cache", 50, context));

    value = ec_mem_cache_alloc(&mem_cache, context);
    ASSERT_TEST(value != NULL);

    if (value)
    {
        // Get a ref and then free the value.  This should keep the the item alive until we call put.
        ec_mem_cache_get(value, context);
        ASSERT_TEST(ec_mem_cache_ref_count(value, context) == 2);
        ec_mem_cache_disown(value, context);

        // Sleep to give the refcount logic time to switch to atomic mode
        msleep(100);
        // This still occasionally fails
        ASSERT_TEST(ec_mem_cache_get_allocated_count(&mem_cache, context) == 1);
        ec_mem_cache_put(value, context);

        // This still occasionally fails even after the sleep
        ASSERT_TEST(ec_mem_cache_get_allocated_count(&mem_cache, context) == 0);
    }

    ASSERT_TEST(ec_mem_cache_destroy(&mem_cache, context) == 0);


    return passed;

CATCH_DEFAULT:
    return false;
}

static int delete_cb_called;
static void __delete_cb(void *value, ProcessContext *context)
{
    ++delete_cb_called;
}

bool __init test__mem_cache_delete_cb(ProcessContext *context)
{
    bool passed = true;
    CB_MEM_CACHE mem_cache = {
        .delete_callback = __delete_cb
    };
    void *value1 = NULL;
    void *value2 = NULL;

    ASSERT_TRY(ec_mem_cache_create(&mem_cache, "test cache", 50, context));

    value1 = ec_mem_cache_alloc(&mem_cache, context);
    value2 = ec_mem_cache_alloc(&mem_cache, context);
    ASSERT_TEST(value1 != NULL);
    ASSERT_TEST(value2 != NULL);

    delete_cb_called = 0;
    ec_mem_cache_disown(value1, context);
    ec_mem_cache_disown(value2, context);

    ASSERT_TEST(ec_mem_cache_destroy(&mem_cache, context) == 0);
    ASSERT_TEST(delete_cb_called == 2);


    return passed;

CATCH_DEFAULT:
    return false;
}