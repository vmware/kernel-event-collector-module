// Copyright 2021 VMware Inc.  All rights reserved.

#include "run-tests.h"
#include "mem-cache.h"

bool __init test__mem_cache_create_destroy(ProcessContext *context);
bool __init test__mem_cache_alloc(ProcessContext *context);

bool __init test__mem_cache(ProcessContext *context)
{
    DECLARE_TEST();

    RUN_TEST(test__mem_cache_create_destroy(context));
    RUN_TEST(test__mem_cache_alloc(context));

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
        ec_mem_cache_free(value, context);
    }

    ASSERT_TEST(ec_mem_cache_destroy(&mem_cache, context) == 0);


    return passed;

CATCH_DEFAULT:
    return false;
}