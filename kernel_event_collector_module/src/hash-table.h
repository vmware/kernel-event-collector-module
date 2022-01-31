/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/hash.h>
#include <linux/list.h>

#include "version.h"
#include "percpu-util.h"
#include "mem-cache.h"

#define  ACTION_CONTINUE   0
#define  ACTION_STOP       1
#define  ACTION_DELETE     4

// hash-table-generic provides interfaces for hash tables. It supports arbitary
// key length. In order to use this hash table, you need to create a struct that
// contains a struct hlist_node called 'link'. Then you can add one, or more
// fields as the key. Last, add fields as value. The order does matter here,
// because the implementation will use the address of link plus the offset to
// get the key. So you need to make sure 'link' is before the key, and the key
// is before the value. Also be careful of struct alignment here. Memset to 0 is
// recommended after creating a key. See hash_table_test for usage.
//
typedef void (*hashtbl_delete_cb)(void *datap, ProcessContext *context);

// Optionally get a handle pointer
typedef void *(*hashtbl_handle_cb)(void *datap, ProcessContext *context);

typedef void (*hashtbl_printval_cb)(void *datap, ProcessContext *context);
typedef bool (*hashtbl_find_verify_cb)(void *datap, void *key, ProcessContext *context);

typedef struct hashbtl_bkt {
    uint64_t lock;
    struct hlist_head head;
    uint64_t itemCount;
} HashTableBkt;

typedef struct hashtbl {
    HashTableBkt *tablePtr;
    struct list_head   genTables;
    const char *name;
    uint64_t   numberOfBuckets;
    uint64_t   datasize;
    uint64_t   lruSize;
    uint32_t   secret;
    struct percpu_counter tableInstance;
    bool initialized;
    int key_len;
    int value_len;
    CB_MEM_CACHE hash_cache;
    int key_offset;
    size_t base_size;
    bool debug_logging;
    hashtbl_delete_cb delete_callback; // Delete private data in object
    hashtbl_handle_cb handle_callback; // Generate a private handle to the object (get ref counts, etc..)
    hashtbl_printval_cb printval_callback; // Debug print of object
    hashtbl_find_verify_cb find_verify_callback; // Verify found object matches extra criteria (called locked without increasing ref)
} HashTbl;

bool ec_hashtbl_startup(ProcessContext *context);
void ec_hashtbl_shutdown(ProcessContext *context);

typedef int (*hashtbl_for_each_cb)(HashTbl *tblp, void *datap, void *priv, ProcessContext *context);

bool ec_hashtbl_init(
    HashTbl        *hashTblp,
    ProcessContext *context);
void ec_hashtbl_destroy(HashTbl *tblp, ProcessContext *context);

void *ec_hashtbl_alloc(HashTbl *tblp, ProcessContext *context);
void ec_hashtbl_free(HashTbl *tblp, void *datap, ProcessContext *context);
void *ec_hashtbl_get(HashTbl *tblp, void *datap, ProcessContext *context);
int64_t ec_hashtbl_ref_count(HashTbl *tblp, void *datap, ProcessContext *context);
void ec_hashtbl_cache_ref_str(HashTbl *tblp, void *datap, char *buffer, size_t size, ProcessContext *context);

// Decrements reference count and frees datap if reference count is 0
void ec_hashtbl_put(HashTbl *tblp, void *datap, ProcessContext *context);


int64_t ec_hashtbl_get_count(HashTbl *hashTblp, ProcessContext *context);
int ec_hashtbl_add(HashTbl *tblp, void *datap, ProcessContext *context);

// Like ec_hashtbl_add but returns -EEXIST on a duplicate entry.
// Caller responsible for freeing on failure to add entry.
int ec_hashtbl_add_safe(HashTbl *hashTblp, void *datap, ProcessContext *context);

// Finds and removes data for key from hash table. Caller must put or free return.
void *ec_hashtbl_del_by_key(HashTbl *tblp, void *key, ProcessContext *context);

// Removes datap from hash table but does not free it
// Free with ec_hashtbl_put
void ec_hashtbl_del(HashTbl *tblp, void *datap, ProcessContext *context);

void *ec_hashtbl_find(HashTbl *tblp, void *key, ProcessContext *context);

void ec_hashtbl_clear(HashTbl *tblp, ProcessContext *context);
void ec_hashtbl_write_for_each(HashTbl *hashTblp, hashtbl_for_each_cb callback, void *priv, ProcessContext *context);
void ec_hashtbl_read_for_each(HashTbl *hashTblp, hashtbl_for_each_cb callback, void *priv, ProcessContext *context);
int ec_hashtbl_show_proc_cache(struct seq_file *m, void *v);
size_t ec_hashtbl_get_memory(ProcessContext *context);
void ec_hashtbl_debug_on(void);
void ec_hashtbl_debug_off(void);

bool ec_hashtbl_read_bkt_lock(HashTbl *hashTblp, void *key, void **datap, HashTableBkt **bkt,
                              ProcessContext *context);
void ec_hashtbl_read_bkt_unlock(HashTableBkt *bkt, ProcessContext *context);

bool ec_hashtbl_write_bkt_lock(HashTbl *hashTblp, void *key, void **datap, HashTableBkt **bkt,
                               ProcessContext *context);
void ec_hashtbl_write_bkt_unlock(HashTableBkt *bkt, ProcessContext *context);

void ec_hashtbl_read_lock(HashTbl *hashTblp, void *key, ProcessContext *context);
void ec_hashtbl_read_unlock(HashTbl *hashTblp, void *key, ProcessContext *context);
void ec_hashtbl_write_lock(HashTbl *hashTblp, void *key, ProcessContext *context);
void ec_hashtbl_write_unlock(HashTbl *hashTblp, void *key, ProcessContext *context);

// Do not call this directly unless you wrap around ec_hashtbl_write_bkt_lock
int ec_hashtbl_del_lockheld(HashTbl *hashTblp, HashTableBkt *bucketp, void *datap, ProcessContext *context);

// Debug Functions
typedef void (*hastable_print_func)(void *, const char *, ...);

void ec_hastable_bkt_show(HashTbl *hashTblp, hastable_print_func _print, void *m, ProcessContext *context);
