/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/list.h>
#include <linux/seq_file.h>

#include "percpu-util.h"
#include "process-context.h"

#define CB_MEM_CACHE_NAME_LEN    43

typedef void (*cache_delete_cb)(void *value, ProcessContext *context);
typedef void (*cache_printval_cb)(void *value, ProcessContext *context);

typedef struct CB_MEM_CACHE {
    struct list_head   node;
    struct list_head   allocation_list;
    uint64_t           lock;
    struct percpu_counter allocated_count;
    struct percpu_counter waiting_for_dealloc;
    struct kmem_cache *kmem_cache;
    uint32_t           object_size;
    uint8_t            name[CB_MEM_CACHE_NAME_LEN + 1];
    cache_delete_cb    delete_callback;
    cache_printval_cb  printval_callback;
} CB_MEM_CACHE;

// checkpatch-ignore: COMPLEX_MACRO
#define CB_MEM_CACHE_INIT() {  \
    .delete_callback = NULL,   \
    .printval_callback = NULL, \
}
// checkpatch-no-ignore: COMPLEX_MACRO


bool ec_mem_cache_init(ProcessContext *context);
void ec_mem_cache_shutdown(ProcessContext *context);
size_t ec_mem_cache_get_memory_usage(ProcessContext *context);
int ec_mem_cache_show(struct seq_file *m, void *v);

bool ec_mem_cache_create(CB_MEM_CACHE *cache, const char *name, size_t size, ProcessContext *context);
uint64_t ec_mem_cache_destroy(CB_MEM_CACHE *cache, ProcessContext *context);

void *ec_mem_cache_alloc(CB_MEM_CACHE *cache, ProcessContext *context);
void ec_mem_cache_disown(void *value, ProcessContext *context);
bool ec_mem_cache_is_owned(void *value, ProcessContext *context);
void ec_mem_cache_get(void *value, ProcessContext *context);
void ec_mem_cache_put(void *value, ProcessContext *context);
int64_t ec_mem_cache_ref_count(void *value, ProcessContext *context);
int64_t ec_mem_cache_get_allocated_count(CB_MEM_CACHE *cache, ProcessContext *context);
