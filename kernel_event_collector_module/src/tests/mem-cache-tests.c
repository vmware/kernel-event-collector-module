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
    CB_MEM_CACHE mem_cache;

    CANCEL(ec_mem_cache_create(&mem_cache, "test cache", 50, context), false);
    ec_mem_cache_destroy(&mem_cache, context, NULL);

    return true;
}

bool __init test__mem_cache_alloc(ProcessContext *context)
{
    CB_MEM_CACHE mem_cache;
    void *value = NULL;
    bool valid_value = false;
    bool valid_size1 = false;
    bool valid_size2 = false;

    CANCEL(ec_mem_cache_create(&mem_cache, "test cache", 50, context), false);

    value = ec_mem_cache_alloc(&mem_cache, context);

    valid_value = !!value;

    if (value)
    {
        valid_size1 = ec_mem_cache_get_allocated_count(&mem_cache, context) == 1;
        ec_mem_cache_free(&mem_cache, value, context);
        valid_size2 = ec_mem_cache_get_allocated_count(&mem_cache, context) == 0;
    }

    ec_mem_cache_destroy(&mem_cache, context, NULL);

    return valid_value && valid_size1 && valid_size2;
}