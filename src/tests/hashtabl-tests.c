/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#include "hash-table-generic.h"
#include "run-tests.h"

typedef struct table_key {
    int id;
} TableKey;

typedef struct table_value {
    char a[16];
} TableValue;

typedef struct entry {
    HashTableNode      link;
    struct table_key   key;
    atomic64_t         reference_count;
    struct table_value value;
} Entry;

static HashTbl * init_hashtbl(ProcessContext *context, int refcount_offset, hashtbl_delete_cb delete_callback)
{
    return hashtbl_init_generic(context,
                              1024,
                              sizeof(Entry),
                              sizeof(Entry),
                              "hash_table_testing",
                              sizeof(TableKey),
                              offsetof(Entry, key),
                              offsetof(Entry, link),
                              refcount_offset,
                              delete_callback);
}

bool __init test__hash_table(ProcessContext *context)
{
    bool passed = false;
    HashTbl *table = init_hashtbl(context, HASHTBL_DISABLE_REF_COUNT, NULL);

    int size = 102400;
    int i, result;
    struct table_key *keys = (struct table_key *)cb_mem_cache_alloc_generic(sizeof(struct table_key) * size, context);
    struct table_value *values = (struct table_value *)cb_mem_cache_alloc_generic(sizeof(struct table_value) * size, context);
    struct entry *entry_ptr;

    //Test hashtbl_alloc and hashtbl_add
    for (i = 0; i < size; i++)
    {
        keys[i].id = i;

        get_random_bytes(&values[i], sizeof(struct table_value));
        entry_ptr = (struct entry *)hashtbl_alloc_generic(table, context);
        if(entry_ptr == NULL)
        {
            pr_alert("Failt to alloc %d\n", i);
            goto test_exit;
        }

        entry_ptr->key.id = i;
        memcpy(&entry_ptr->value, &values[i], sizeof(struct table_value));
        result = hashtbl_add_generic(table, entry_ptr, context);
        if(result != 0)
        {
            hashtbl_free_generic(table, entry_ptr, context);
            pr_alert("Add fails %d\n", i);
            goto test_exit;
        }
    }

    //Test hashtbl_get
    for (i = 0; i < size; i++)
    {
        entry_ptr = hashtbl_get_generic(table, &keys[i], context);

        if (!entry_ptr)
        {
            pr_alert("hashtbl_get_generic failed %d %d\n", i, keys[i].id);
        }

        if (memcmp(&entry_ptr->value, &values[i], sizeof(struct table_key)) != 0)
        {
            pr_alert("Get value does not match %d %d\n", i, keys[i].id);
            goto test_exit;
        }
    }

    //Test hastbl_del and hashtbl_free
    for (i = 0; i < size; i++)
    {
        entry_ptr = hashtbl_del_by_key_generic(table, &keys[i], context);
        if (entry_ptr == NULL)
        {
            pr_alert("Fail to find the element to be deleted\n");
            goto test_exit;
        }

        hashtbl_free_generic(table, entry_ptr, context);

        entry_ptr = hashtbl_get_generic(table, &keys[i], context);
        if (entry_ptr != NULL)
        {
            pr_alert("Delete fails %d\n", i);
            goto test_exit;
        }
    }

    pr_alert("Hash table tests all passed.\n");
    passed = true;
test_exit:
    cb_mem_cache_free_generic(keys);
    cb_mem_cache_free_generic(values);
    hashtbl_shutdown_generic(table, context);

    return passed;
}

bool __init test__hashtbl_double_del(ProcessContext *context)
{
    bool passed = false;
    HashTbl *table = init_hashtbl(context, HASHTBL_DISABLE_REF_COUNT, NULL);
    Entry *tdata   = NULL;

    ASSERT_TRY(table);

    tdata = (Entry *)hashtbl_alloc_generic(table, context);
    TRY_MSG(tdata, DL_ERROR, "hashtbl_alloc_generic failed");

    ASSERT_TRY(hashtbl_add_generic(table, tdata, context) == 0);

    // delete tdata so it gets deleted again below
    hashtbl_del_generic(table, tdata, context);

    passed = true;
CATCH_DEFAULT:
    if (table)
    {
        if(tdata)
        {
            hashtbl_del_generic(table, tdata, context);
            hashtbl_free_generic(table, tdata, context);
        }
        hashtbl_shutdown_generic(table, context);
    }

    return passed;
}

bool __init test__hashtbl_refcount_double_del(ProcessContext *context)
{
    bool passed = false;
    HashTbl *table  = init_hashtbl(context, offsetof(Entry, reference_count), NULL);
    Entry *tdata = NULL;

    ASSERT_TRY(table);

    tdata = (Entry *)hashtbl_alloc_generic(table, context);
    TRY_MSG(tdata, DL_ERROR, "hashtbl_alloc_generic failed");

    atomic64_set(&tdata->reference_count, 1);

    TRY_MSG(hashtbl_add_generic(table, tdata, context) == 0, DL_ERROR, "hashtbl_add_generic failed");

    // delete tdata so it gets deleted again below
    hashtbl_del_generic(table, tdata, context);

    passed = true;
CATCH_DEFAULT:
    if (tdata)
    {
        hashtbl_del_generic(table, tdata, context);
        hashtbl_put_generic(table, tdata, context);
    }
    hashtbl_shutdown_generic(table, context);

    return passed;
}

static bool _delete_callback_called __initdata;

static void __init _hashtbl_delete_callback(void *data, ProcessContext *context)
{
    _delete_callback_called = true;
}

bool __init test__hashtbl_refcount(ProcessContext *context)
{
    bool passed = false;
    HashTbl *table = init_hashtbl(context, offsetof(Entry, reference_count), _hashtbl_delete_callback);
    Entry *tdata   = NULL;
    TableKey key;

    ASSERT_TRY(table);

    tdata = (Entry *)hashtbl_alloc_generic(table, context);
    ASSERT_TRY(tdata);

    tdata->key.id = 1;
    atomic64_set(&tdata->reference_count, 1);

    ASSERT_TRY(hashtbl_add_generic(table, tdata, context) == 0);
    // refcount 2

    key.id = 1;
    ASSERT_TRY(hashtbl_get_generic(table, &key, context) == tdata);
    // refcount 3

    _delete_callback_called = false;
    hashtbl_put_generic(table, tdata, context);
    // refcount 2
    ASSERT_TRY(!_delete_callback_called);

    // calls put
    hashtbl_del_generic(table, tdata, context);
    // refcount 1
    ASSERT_TRY(!_delete_callback_called);

    // The reference count should be 1 now and this put should result in a free
    hashtbl_put_generic(table, tdata, context);
    // refcount 0 should have been freed
    ASSERT_TRY(_delete_callback_called);
    tdata = NULL;
    passed = true;

CATCH_DEFAULT:
    if (table)
    {
        if(tdata)
        {
            hashtbl_del_generic(table, tdata, context);
            hashtbl_put_generic(table, tdata, context);
        }
        hashtbl_shutdown_generic(table, context);
    }

    return passed;
}

// Attempt to add two entries and verify -EEXIST is returned
bool __init test__hashtbl_add_duplicate(ProcessContext *context)
{
    bool passed = false;
    Entry *tdata   = NULL;
    Entry *tdata2  = NULL;
    HashTbl *table = init_hashtbl(context, HASHTBL_DISABLE_REF_COUNT, NULL);

    ASSERT_TRY(table);

    tdata = (Entry *)hashtbl_alloc_generic(table, context);
    tdata2 = (Entry *)hashtbl_alloc_generic(table, context);
    ASSERT_TRY(tdata);
    ASSERT_TRY(tdata2);

    tdata->key.id = 1;
    tdata2->key.id = 1;

    ASSERT_TRY(hashtbl_add_generic(table, tdata, context) == 0);
    ASSERT_TRY(hashtbl_add_generic_safe(table, tdata2, context) == -EEXIST);
    passed = true;

CATCH_DEFAULT:
    if (table)
    {
        if(tdata)
        {
            hashtbl_del_generic(table, tdata, context);
            hashtbl_free_generic(table, tdata, context);
        }
        if(tdata2)
        {
            hashtbl_del_by_key_generic(table, &tdata2->key, context);
            hashtbl_free_generic(table, tdata2, context);
        }
        hashtbl_shutdown_generic(table, context);
    }
    return passed;
}
