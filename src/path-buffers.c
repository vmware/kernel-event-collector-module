// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "path-buffers.h"
#include "mem-cache.h"
#include "process-context.h"
#include "task-helper.h"

#include <linux/limits.h>

struct STRING_NODE {
    struct list_head  listEntry;
    char  path[PATH_MAX+1];
};

static CB_MEM_CACHE s_string_pool;

bool path_buffers_init(ProcessContext *context)
{
    return cb_mem_cache_create(&s_string_pool, "path_string_pool", sizeof(struct STRING_NODE), context);
}

void path_buffers_shutdown(ProcessContext *context)
{
    cb_mem_cache_destroy(&s_string_pool, context, NULL);
}

// Get a string buffer from the the list, or alloc a new one.
char *get_path_buffer(ProcessContext *context)
{
    struct STRING_NODE *node   = NULL;

    node = (struct STRING_NODE *)cb_mem_cache_alloc(&s_string_pool, context);
    if (node)
    {
        node->path[0]        = 0;
        node->path[PATH_MAX] = 0;
    }
    return (node ? node->path : NULL);
}

void put_path_buffer(char *buffer)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    if (buffer)
    {
        cb_mem_cache_free(&s_string_pool, container_of((void *)buffer, struct STRING_NODE, path), &context);
    }
}
