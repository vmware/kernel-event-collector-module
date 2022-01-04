/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright 2021 VMware Inc.  All rights reserved. */

#pragma once

#include "process-context.h"

bool ec_mem_init(ProcessContext *context);
void ec_mem_shutdown(ProcessContext *context);
int64_t ec_mem_allocated_count(ProcessContext *context);
int64_t ec_mem_allocated_size(ProcessContext *context);

/* private */
void *__ec_mem_alloc(const size_t size, ProcessContext *context, bool doVirtualAlloc, const char *fn, uint32_t line);
void __ec_mem_disown(void *value, const char *fn, uint32_t line);
void __ec_mem_put(void *value, const char *fn, uint32_t line);
/* end private */


// Define this to enable memory leak debugging
//  This will track all memory allocations in a list with record of the source function
//  NOTE: This list is not protectd by a lock, so it is absolutely for debug only.
//        a. Our locks allocate memory
//        b. The free function does not currently accept a `context`, and always using GFP_ATOMIC causes issues
#ifdef MEM_DEBUG
#  define ec_mem_alloc(SIZE, CONTEXT) __ec_mem_alloc(SIZE, CONTEXT, false, __func__, __LINE__)
#  define ec_mem_valloc(SIZE, CONTEXT) __ec_mem_alloc(SIZE, CONTEXT, true, __func__, __LINE__)
#  define ec_mem_free(VALUE) __ec_mem_disown(VALUE, __func__, __LINE__)
#  define ec_mem_disown(VALUE) __ec_mem_disown(VALUE, __func__, __LINE__)
#  define ec_mem_put(VALUE) __ec_mem_put(VALUE, __func__, __LINE__)
#else
#  define ec_mem_alloc(SIZE, CONTEXT) __ec_mem_alloc(SIZE, CONTEXT, false, NULL, __LINE__)
#  define ec_mem_valloc(SIZE, CONTEXT) __ec_mem_alloc(SIZE, CONTEXT, true, NULL, __LINE__)
#  define ec_mem_free(VALUE) __ec_mem_disown(VALUE, NULL, __LINE__)
#  define ec_mem_disown(VALUE) __ec_mem_disown(VALUE, NULL, __LINE__)
#  define ec_mem_put(VALUE) __ec_mem_put(VALUE, NULL, __LINE__)
#endif

void *ec_mem_get(void *value, ProcessContext *context);
size_t ec_mem_size(const void *value);
char *ec_mem_strdup(const char *src, ProcessContext *context);
char *ec_mem_strdup_x(const char *src, size_t *len, ProcessContext *context);
