// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 VMware Inc.  All rights reserved.

#include "plru.h"
#include "run-tests.h"

bool __init test__plru_init(ProcessContext *context);
bool __init test__plru_find_inactive(ProcessContext *context);
bool __init test__plru_mark_active(ProcessContext *context);

bool __init test__plru(ProcessContext *context)
{
    DECLARE_TEST();

    RUN_TEST(test__plru_init(context));
    RUN_TEST(test__plru_find_inactive(context));
    RUN_TEST(test__plru_mark_active(context));

    RETURN_RESULT();
}

bool __init test__plru_init(ProcessContext *context)
{
    bool passed = false;
    PLruTree plru = {};

    TRY_MSG(ec_plru_init(&plru, 8, NULL, context), DL_ERROR, "ec_plru [%s:%d] init failed", __func__, __LINE__);

    TRY_MSG(plru.head != NULL, DL_ERROR, "ec_plru [%s:%d] allocation failed", __func__, __LINE__);

    passed = true;

CATCH_DEFAULT:
    return passed;
}

bool __init test__plru_find_inactive(ProcessContext *context)
{
    bool passed = false;
    PLruTree plru = {};
    int64_t index;
    int64_t expected_index;

    ec_plru_init(&plru, 8, NULL, context);

    expected_index = 0;
    index = ec_plru_find_inactive_leaf(&plru, context);
    TRY_MSG(index == expected_index, DL_ERROR, "ec_plru [%s:%d] unexpected index [%lld != %lld]", __func__, __LINE__, expected_index, index);

    expected_index = 4;
    index = ec_plru_find_inactive_leaf(&plru, context);
    TRY_MSG(index == expected_index, DL_ERROR, "ec_plru [%s:%d] unexpected index [%lld != %lld]", __func__, __LINE__, expected_index, index);

    passed = true;

CATCH_DEFAULT:
    return passed;
}

bool __init test__plru_mark_active(ProcessContext *context)
{
    bool passed = false;
    PLruTree plru = {};
    int64_t index;
    int64_t expected_index;

    ec_plru_init(&plru, 8, NULL, context);

    ec_plru_mark_active_path(&plru, 2, context);

    expected_index = 4;
    index = ec_plru_find_inactive_leaf(&plru, context);
    TRY_MSG(index == expected_index, DL_ERROR, "ec_plru [%s:%d] unexpected index [%lld != %lld]", __func__, __LINE__, expected_index, index);

    passed = true;

CATCH_DEFAULT:
    return passed;
}