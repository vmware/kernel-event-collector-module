/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#include "hash-table.h"
#include "run-tests.h"
#include "mem-alloc.h"

typedef struct table_key {
    uint64_t id;
} TableKey;

typedef struct table_value {
    char a[16];
} TableValue;

typedef struct entry {
    struct table_key   key;
    struct table_value value;
} Entry;

#define HASH_TBL_INIT() {                                       \
        .numberOfBuckets = 1024,                                \
        .name = "hash_table_testing",                           \
        .datasize = sizeof(Entry),                              \
        .key_len     = sizeof(TableKey),                        \
        .key_offset  = offsetof(Entry, key),                    \
        .delete_callback = __ec_test_hashtbl_delete_callback,   \
}

static int _delete_callback_called __initdata;

bool __init test__hashtbl_init_destroy(ProcessContext *context);
bool __init test__hashtbl_bad_destroy(ProcessContext *context);
bool __init test__hashtbl_alloc_free(ProcessContext *context);
bool __init test__hashtbl_add_destroy(ProcessContext *context);
bool __init test__hashtbl_add_del(ProcessContext *context);


bool __init test__hashtbl_add_get_del(ProcessContext *context);
bool __init test__hashtbl_double_del(ProcessContext *context);
bool __init test__hashtbl_refcount(ProcessContext *context);
bool __init test__hashtbl_add_duplicate(ProcessContext *context);
bool __init test__hashtbl_lru_lookup(ProcessContext *context);
bool __init test__hashtbl_lru_one_bucket(ProcessContext *context);
bool __init test__hashtbl_lru_many_buckets(ProcessContext *context);
bool __init test__hashtbl_lru_one_bucket_activity(ProcessContext *context);

static void __init __vprintk(void *, const char *, ...);
static void __init __ec_test_hashtbl_delete_callback(void *data, ProcessContext *context);

bool __init test__hash_table(ProcessContext *context)
{
    DECLARE_TEST();

    RUN_TEST(test__hashtbl_init_destroy(context));
    RUN_TEST(test__hashtbl_bad_destroy(context));
    RUN_TEST(test__hashtbl_alloc_free(context));
    RUN_TEST(test__hashtbl_add_destroy(context));
    RUN_TEST(test__hashtbl_add_del(context));
    RUN_TEST(test__hashtbl_add_get_del(context));
    RUN_TEST(test__hashtbl_double_del(context));
    RUN_TEST(test__hashtbl_refcount(context));
    RUN_TEST(test__hashtbl_add_duplicate(context));
    RUN_TEST(test__hashtbl_lru_lookup(context));
    RUN_TEST(test__hashtbl_lru_one_bucket(context));
    RUN_TEST(test__hashtbl_lru_many_buckets(context));
    RUN_TEST(test__hashtbl_lru_one_bucket_activity(context));
    RETURN_RESULT();
}

bool __init test__hashtbl_init_destroy(ProcessContext *context)
{
    bool passed = false;
    HashTbl hash_table = HASH_TBL_INIT();

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));


    passed = true;
CATCH_DEFAULT:
    ec_hashtbl_destroy(&hash_table, context);

    return passed;
}

bool __init test__hashtbl_bad_destroy(ProcessContext *context)
{
    HashTbl hash_table = HASH_TBL_INIT();

    ec_hashtbl_destroy(&hash_table, context);

    return true;
}

bool __init test__hashtbl_alloc_free(ProcessContext *context)
{
    bool passed = false;
    struct entry *entry_ptr;
    HashTbl hash_table = HASH_TBL_INIT();

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    entry_ptr = (struct entry *)ec_hashtbl_alloc(&hash_table, context);
    ASSERT_TRY(entry_ptr != NULL);

    ec_hashtbl_free(&hash_table, entry_ptr, context);


    passed = true;
CATCH_DEFAULT:
    ec_hashtbl_destroy(&hash_table, context);

    return passed;
}

bool __init test__hashtbl_add_destroy(ProcessContext *context)
{
    bool passed = false;
    struct entry *entry_ptr = NULL;
    HashTbl hash_table = HASH_TBL_INIT();

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    entry_ptr = (struct entry *)ec_hashtbl_alloc(&hash_table, context);
    ASSERT_TRY(entry_ptr != NULL);

    entry_ptr->key.id = 1;

    ASSERT_TRY(ec_hashtbl_add(&hash_table, entry_ptr, context) == 0);
    ASSERT_TEST(ec_hashtbl_get_count(&hash_table, context) == 1);

    ec_hashtbl_put(&hash_table, entry_ptr, context);

    passed = true;
CATCH_DEFAULT:
    ec_hashtbl_destroy(&hash_table, context);

    return passed;
}

bool __init test__hashtbl_add_del(ProcessContext *context)
{
    bool passed = false;
    struct entry *entry_ptr = NULL;
    HashTbl hash_table = HASH_TBL_INIT();

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    entry_ptr = (struct entry *)ec_hashtbl_alloc(&hash_table, context);
    ASSERT_TRY(entry_ptr != NULL);

    entry_ptr->key.id = 1;

    ASSERT_TRY(ec_hashtbl_add(&hash_table, entry_ptr, context) == 0);


    ec_hashtbl_del(&hash_table, entry_ptr, context);
    ASSERT_TEST(ec_hashtbl_get_count(&hash_table, context) == 0);

    ec_hashtbl_put(&hash_table, entry_ptr, context);

    passed = true;
CATCH_DEFAULT:
    ec_hashtbl_destroy(&hash_table, context);

    return passed;
}

bool __init test__hashtbl_add_get_del(ProcessContext *context)
{
    bool passed = false;
    HashTbl hash_table = HASH_TBL_INIT();

    int size = 102400;
    int i, result;
    struct table_key *keys = (struct table_key *)ec_mem_alloc(sizeof(struct table_key) * size, context);
    struct table_value *values = (struct table_value *)ec_mem_alloc(sizeof(struct table_value) * size, context);
    struct entry *entry_ptr;

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    //Test ec_hashtbl_alloc and ec_hashtbl_add
    for (i = 0; i < size; i++)
    {
        keys[i].id = i;

        get_random_bytes(&values[i], sizeof(struct table_value));
        entry_ptr = (struct entry *)ec_hashtbl_alloc(&hash_table, context);
        if(entry_ptr == NULL)
        {
            pr_alert("Failt to alloc %d\n", i);
            goto CATCH_DEFAULT;
        }

        entry_ptr->key.id = i;
        memcpy(&entry_ptr->value, &values[i], sizeof(struct table_value));
        result = ec_hashtbl_add(&hash_table, entry_ptr, context);
        if(result != 0)
        {
            ec_hashtbl_free(&hash_table, entry_ptr, context);
            pr_alert("Add fails %d\n", i);
            goto CATCH_DEFAULT;
        }
        ec_hashtbl_put(&hash_table, entry_ptr, context);
    }

    //Test ec_hashtbl_get
    for (i = 0; i < size; i++)
    {
        int result = 0;

        entry_ptr = ec_hashtbl_find(&hash_table, &keys[i], context);

        if (!entry_ptr)
        {
            pr_alert("ec_hashtbl_find failed %d %llu\n", i, keys[i].id);
        }

        result = memcmp(&entry_ptr->value, &values[i], sizeof(struct table_key));
        ec_hashtbl_put(&hash_table, entry_ptr, context);

        if (result != 0)
        {
            pr_alert("Get value does not match %d %llu\n", i, keys[i].id);
            goto CATCH_DEFAULT;
        }
    }

    //Test hastbl_del and ec_hashtbl_free
    for (i = 0; i < size; i++)
    {
        entry_ptr = ec_hashtbl_del_by_key(&hash_table, &keys[i], context);
        if (entry_ptr == NULL)
        {
            pr_alert("Fail to find the element to be deleted\n");
            goto CATCH_DEFAULT;
        }

        ec_hashtbl_put(&hash_table, entry_ptr, context);

        entry_ptr = ec_hashtbl_find(&hash_table, &keys[i], context);
        if (entry_ptr != NULL)
        {
            pr_alert("Delete fails %d\n", i);
            ec_hashtbl_put(&hash_table, entry_ptr, context);
            goto CATCH_DEFAULT;
        }
    }

    passed = true;
CATCH_DEFAULT:
    ec_mem_free(keys);
    ec_mem_free(values);
    ec_hashtbl_destroy(&hash_table, context);

    return passed;
}

bool __init test__hashtbl_double_del(ProcessContext *context)
{
    bool passed = true;
    Entry *tdata   = NULL;
    HashTbl hash_table = HASH_TBL_INIT();

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    tdata = (Entry *)ec_hashtbl_alloc(&hash_table, context);
    TRY_MSG(tdata, DL_ERROR, "ec_hashtbl_alloc failed");

    ASSERT_TEST(ec_hashtbl_add(&hash_table, tdata, context) == 0);

    // delete tdata so it gets deleted again below
    ec_hashtbl_del(&hash_table, tdata, context);
    ec_hashtbl_del(&hash_table, tdata, context);
    ec_hashtbl_put(&hash_table, tdata, context);

CATCH_DEFAULT:
    ec_hashtbl_destroy(&hash_table, context);

    return passed;
}

bool __init test__hashtbl_refcount(ProcessContext *context)
{
    bool passed = true;
    Entry *tdata1   = NULL;
    Entry *tdata2   = NULL;
    TableKey key;
    HashTbl hash_table = HASH_TBL_INIT();

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    tdata1 = (Entry *)ec_hashtbl_alloc(&hash_table, context);
    ASSERT_TRY(tdata1);

    tdata1->key.id = 1;

    ASSERT_TEST(ec_hashtbl_add(&hash_table, tdata1, context) == 0);
    // refcount 2

    key.id = 1;
    tdata2 = ec_hashtbl_find(&hash_table, &key, context);
    ASSERT_TEST(tdata2 == tdata1);
    // refcount 3

    _delete_callback_called = 0;
    ec_hashtbl_put(&hash_table, tdata1, context);
    tdata1 = NULL;
    // refcount 2
    msleep(50); // This can be async, so sleep to be sure
    ASSERT_TEST(_delete_callback_called == 0);

    // calls put
    ec_hashtbl_del(&hash_table, tdata2, context);
    // refcount 1
    msleep(50); // This can be async, so sleep to be sure
    ASSERT_TEST(_delete_callback_called == 0);

    // The reference count should be 1 now and this put should result in a free
    ec_hashtbl_put(&hash_table, tdata2, context);
    // refcount 0 should have been freed
    msleep(50); // This can be async, so sleep to be sure
    ASSERT_TEST(_delete_callback_called == 1);
    tdata2 = NULL;

CATCH_DEFAULT:
    ec_hashtbl_destroy(&hash_table, context);

    return passed;
}

// Attempt to add two entries and verify -EEXIST is returned
bool __init test__hashtbl_add_duplicate(ProcessContext *context)
{
    bool passed = false;
    Entry *tdata   = NULL;
    Entry *tdata2  = NULL;
    HashTbl hash_table = HASH_TBL_INIT();

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    tdata = (Entry *)ec_hashtbl_alloc(&hash_table, context);
    tdata2 = (Entry *)ec_hashtbl_alloc(&hash_table, context);
    ASSERT_TRY(tdata);
    ASSERT_TRY(tdata2);

    tdata->key.id = 1;
    tdata2->key.id = 1;

    ASSERT_TRY(ec_hashtbl_add(&hash_table, tdata, context) == 0);
    ASSERT_TRY(ec_hashtbl_add_safe(&hash_table, tdata2, context) == -EEXIST);
    passed = true;

CATCH_DEFAULT:
    if(tdata)
    {
        ec_hashtbl_put(&hash_table, tdata, context);
    }
    if(tdata2)
    {
        ec_hashtbl_free(&hash_table, tdata2, context);
    }
    ec_hashtbl_destroy(&hash_table, context);
    return passed;
}



// how often do we evict a more recent entry?
bool __init __test__hashtbl_lru_lookup(
    uint64_t lru_size,
    uint64_t bucket_size,
    uint64_t insertion_count,
    ProcessContext *context)
{
    bool passed = false;
    Entry *tdata   = NULL;
    int i;
    uint64_t *data;
    int data_size = 1024;
    uint64_t count;
    HashTbl hash_table = HASH_TBL_INIT();

    hash_table.numberOfBuckets = bucket_size;
    hash_table.lruSize = lru_size;
    hash_table.delete_callback = NULL;


    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    data = ec_mem_alloc(data_size * sizeof(uint64_t), context);

    for (i = 0; i < insertion_count; ++i)
    {
        tdata = (Entry *) ec_hashtbl_alloc(&hash_table, context);
        TRY_MSG(tdata, DL_ERROR, "hashtbl [%s:%d] failed to allocate data", __func__, __LINE__);

        if (i % data_size == 0)
        {
            get_random_bytes(data, ec_mem_size(data));
        }
        tdata->key.id = data[i % data_size];

        // This prevents duplicates, which will trigger an access instead
        if (ec_hashtbl_add_safe(&hash_table, tdata, context) != 0)
        {
            ec_hashtbl_free(&hash_table, tdata, context);
            tdata = NULL;
        }
        ec_hashtbl_put(&hash_table, tdata, context);
        tdata = NULL;
    }
    ec_mem_free(data);

    count = ec_hashtbl_get_count(&hash_table, context);
    TRACE(DL_INFO, "hashtbl lru test: lru_size=%llu, bucket_size=%llu, insertions=%llu",
        lru_size, bucket_size, insertion_count);
    ec_hastable_bkt_show(&hash_table, (hastable_print_func)__vprintk, NULL, context);

    passed = true;

CATCH_DEFAULT:
    ec_hashtbl_destroy(&hash_table, context);
    return passed;
}

bool __init test__hashtbl_lru_lookup(ProcessContext *context)
{
    int i;
    bool passed = true;
    uint64_t data[][3] = {
        // LRU Size, Bucket Size, Insertion Count
        { 16, 128, 8192 },
        { 8, 256, 8192 },
        { 4, 512, 8192 },
        { 2, 1024, 8192 },
        { 1, 2048, 8192 },
        { 16, 16384, 1048576},
        { 8, 16384 * 2, 1048576},
        { 4, 16384 * 4, 1048576 },
        { 2, 16384 * 8, 1048576 },
        { 1, 16384 * 16, 1048576 },
        { 0 }
    };
    for (i = 0; data[i][0] != 0; ++i)
    {
        uint64_t lru_size = data[i][0];
        uint64_t bucket_size = data[i][1];
        uint64_t insertion_count = data[i][2];

        passed &= __test__hashtbl_lru_lookup(lru_size, bucket_size, insertion_count, context);
    }

    return passed;
}

bool __add_entry(int key, HashTbl *hash_table, ProcessContext *context)
{
    Entry *tdata   = NULL;

    tdata = (Entry *)ec_hashtbl_alloc(hash_table, context);
    tdata->key.id = key;

    if (ec_hashtbl_add_safe(hash_table, tdata, context) != 0)
    {
        TRACE(DL_ERROR, "Failed to add entry %d", key);
        return false;
    }

    ec_hashtbl_put(hash_table, tdata, context);
    return true;
}

bool __check_entry_exists(HashTbl *hash_table, int key, ProcessContext *context)
{
    Entry *tdata   = NULL;
    TableKey tkey = {.id = key};

    tdata = ec_hashtbl_find(hash_table, &tkey, context);

    ec_hashtbl_put(hash_table, tdata, context);

    return tdata;
}


int __hashtbl_print_cb(HashTbl *tblp, void *data, void *priv, ProcessContext *context)
{
    Entry *tdata = (Entry *)data;

    if (tdata)
    {
        TRACE(DL_INFO, "-- key: %llu", tdata->key.id);
    }

    return ACTION_PRINT;
}

void __hashtbl_delete_callback(void *data, ProcessContext *context)
{
    Entry *tdata = (Entry *)data;

    if (tdata)
    {
        TRACE(DL_INFO, "%s key: %llu", __func__, tdata->key.id);
    } else
    {
        TRACE(DL_INFO, "%s NULL", __func__);
    }
}

bool __init test__hashtbl_lru_one_bucket(ProcessContext *context)
{
    bool passed = false;
    HashTbl hash_table = HASH_TBL_INIT();
    int count;

    hash_table.numberOfBuckets = 1;
    hash_table.lruSize = 3;
    hash_table.delete_callback = __hashtbl_delete_callback;

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    // this should fill all available buckets
    ASSERT_TRY(__add_entry(1, &hash_table, context));
    ASSERT_TRY(__add_entry(2, &hash_table, context));
    ASSERT_TRY(__add_entry(3, &hash_table, context));

    TRACE(DL_INFO, "hashtbl contents:");
    ec_hashtbl_read_for_each(&hash_table, __hashtbl_print_cb, NULL, context);

    count = ec_hashtbl_get_count(&hash_table, context);
    ASSERT_TRY_MSG(count == 3, "count: %d", count);

    ASSERT_TRY(__add_entry(4, &hash_table, context));

    count = ec_hashtbl_get_count(&hash_table, context);
    ASSERT_TRY_MSG(count == 3, "count: %d", count);

    // The last items added should still be there
    ASSERT_TRY(__check_entry_exists(&hash_table, 4, context));

    ASSERT_TRY(__check_entry_exists(&hash_table, 3, context));

    ASSERT_TRY(__check_entry_exists(&hash_table, 2, context));

    // The first item added should not be there
    ASSERT_TRY(!__check_entry_exists(&hash_table, 1, context));

    passed = true;

CATCH_DEFAULT:
    ec_hashtbl_destroy(&hash_table, context);
    return passed;
}

bool __init test__hashtbl_lru_one_bucket_activity(ProcessContext *context)
{
    bool passed = false;
    HashTbl hash_table = HASH_TBL_INIT();
    int i, count;

    hash_table.numberOfBuckets = 1;
    hash_table.lruSize = 3;
    hash_table.delete_callback = __hashtbl_delete_callback;

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    // this should fill all available buckets
    ASSERT_TRY(__add_entry(1, &hash_table, context));
    ASSERT_TRY(__add_entry(2, &hash_table, context));
    ASSERT_TRY(__add_entry(3, &hash_table, context));

    TRACE(DL_INFO, "hashtbl contents:");
    ec_hashtbl_read_for_each(&hash_table, __hashtbl_print_cb, NULL, context);

    count = ec_hashtbl_get_count(&hash_table, context);
    ASSERT_TRY_MSG(count == 3, "count: %d", count);

    // Increase the activity count for item 1
    for (i=0; i < 20; i++)
    {
        ASSERT_TRY(__check_entry_exists(&hash_table, 1, context));
    }

    TRACE(DL_INFO, "hashtbl contents after activity:");
    ec_hashtbl_read_for_each(&hash_table, __hashtbl_print_cb, NULL, context);

    // Add a new entry
    ASSERT_TRY(__add_entry(4, &hash_table, context));

    // Item 1 should have been moved to the top of the list and should not have been evicted
    ASSERT_TRY(__check_entry_exists(&hash_table, 1, context));

    passed = true;

CATCH_DEFAULT:
    ec_hashtbl_destroy(&hash_table, context);
    return passed;
}

bool __init test__hashtbl_lru_many_buckets(ProcessContext *context)
{
    bool passed = false;
    HashTbl hash_table = HASH_TBL_INIT();
    int i, count;
    int key = 0;

    hash_table.numberOfBuckets = 2;
    hash_table.lruSize = 3;
    hash_table.delete_callback = __hashtbl_delete_callback;

    ASSERT_TRY(ec_hashtbl_init(&hash_table, context));

    // fill all available buckets
    for (i=0; i < hash_table.numberOfBuckets * hash_table.lruSize; i++)
    {
        ASSERT_TRY(__add_entry(key++, &hash_table, context));
    }

    TRACE(DL_INFO, "hashtbl contents:");
    ec_hashtbl_read_for_each(&hash_table, __hashtbl_print_cb, NULL, context);

    ASSERT_TRY(__add_entry(100, &hash_table, context));

    count = ec_hashtbl_get_count(&hash_table, context);
    ASSERT_TRY_MSG(count <= hash_table.numberOfBuckets * hash_table.lruSize, "count: %d", count);

    // The last item added should not have been replaced
    ASSERT_TRY(__check_entry_exists(&hash_table, key - 1, context));

    for (i=1; i < hash_table.numberOfBuckets * hash_table.lruSize; i++)
    {
        ASSERT_TRY(__add_entry(100 + i, &hash_table, context));
    }

    TRACE(DL_INFO, "Done with second additions");

    passed = true;

CATCH_DEFAULT:
    ec_hashtbl_destroy(&hash_table, context);
    return passed;
}

static void __init __ec_test_hashtbl_delete_callback(void *data, ProcessContext *context)
{
    ++_delete_callback_called;
}

static void __init __vprintk(void *m, const char *f, ...)
{
	va_list args;

	va_start(args, f);
	vprintk(f, args);
	va_end(args);
}
