// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 VMware Inc.  All rights reserved.

#include "plru.h"
#include "mem-alloc.h"
#include "cb-test.h"

// In a full binary plru, any row will be one more than the sum of all nodes above it.
#define NODE_COUNT(X)  (X - 1)

size_t ec_plru_get_allocation_size(uint64_t leaf_count)
{
    return (NODE_COUNT(leaf_count) * sizeof(PLruNode));
}

bool ec_plru_init(PLruTree *plru, uint64_t leaf_count, void *tree_head, ProcessContext *context)
{
    CANCEL(plru != NULL, false);

    memset(plru, 0, sizeof(PLruTree));

    if (!tree_head)
    {
        tree_head = ec_mem_alloc(ec_plru_get_allocation_size(leaf_count), context);
        CANCEL(tree_head != NULL, false);

        plru->owned_head = tree_head;
    }

    plru->head = tree_head;
    plru->node_count = NODE_COUNT(leaf_count);

    return true;
}

void ec_plru_destroy(PLruTree *plru, ProcessContext *context)
{
    CANCEL_VOID(plru != NULL && plru->head != NULL);

    ec_mem_free(plru->owned_head);
}

#define GET_LEFT_CHILD(X)    (2*X+1)       // 1 based index
#define GET_RIGHT_CHILD(X)   (2*X+2)       // 1 based index
#define GET_PARENT(X)        ((X % 2) / 2) // 1 based index
#define GET_LESS_CHILD(X)    ((X % 2) / 2) // 1 based index

#ifndef READ_ONCE
#define READ_ONCE(X) (X)
#endif

#define ACTIVE_LEFT                 1
#define ACTIVE_RIGHT                0
#define IS_FROM_LEFT(X)             ((READ_ONCE(X) % 2) == 0)
#define IS_ACTIVE_LEFT(X)           (READ_ONCE(X) == ACTIVE_LEFT)
#define CHANGE_ACTIVE_DIRECTION(IS_LEFT, X)  (IS_LEFT ? ACTIVE_RIGHT : ACTIVE_LEFT)

void ec_plru_mark_active_path(PLruTree *plru, uint64_t leaf_index, ProcessContext *context)
{
    int index;

    CANCEL_VOID(plru != NULL && plru->head != NULL);

    // Figure out the plru index
    index = leaf_index + plru->node_count;

    while (index > 0)
    {
        int parent_index = GET_PARENT(index);

        plru->head[parent_index] = IS_FROM_LEFT(index) ? ACTIVE_RIGHT : ACTIVE_LEFT;

        index = parent_index;
    }
}

int64_t ec_plru_find_inactive_leaf(PLruTree *plru, ProcessContext *context)
{
    int index = 0;

    CANCEL(plru != NULL && plru->head != NULL, -1);

    while (index < plru->node_count)
    {
        // We need to walk the inactive path
        bool isActiveLeft = IS_ACTIVE_LEFT(plru->head[index]);
        int child_index = isActiveLeft ? GET_RIGHT_CHILD(index) : GET_LEFT_CHILD(index);

        // Mark this node as active in the direction we are walking
        plru->head[index] = CHANGE_ACTIVE_DIRECTION(isActiveLeft, plru->head[index]);

        // Update the index for the next iteration
        index = child_index;
    }

    return index - plru->node_count;
}
