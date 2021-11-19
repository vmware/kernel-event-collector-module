/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright 2021 VMware Inc.  All rights reserved. */

// The logic for this is based on the Tree Psudo-LRU defined here: https://en.wikipedia.org/wiki/Pseudo-LRU
//
// The basic concept behind this is the consumer has a static sized array where they expect random access, and would like
//  to know which index most likely has not been accessed very recently.  This will not provide the absolute least recently
//  accessed index.
// Each node of the tree has a boolean flag denoting "go left to find a pseudo-LRU element" or "go right to find a
//  pseudo-LRU element".
// * To find a pseudo-LRU element, traverse the tree according to the values of the flags.
// * To update the tree with an access to an item N, traverse the tree to find N and, during the traversal, set the node
//   flags to denote the direction that is opposite to the direction taken.

#pragma once

#include "process-context.h"

#include <linux/types.h>

typedef uint8_t PLruNode;

typedef struct plru_tree {
    PLruNode *head;
    void *owned_head;
    uint64_t node_count;
} PLruTree;

size_t ec_plru_get_allocation_size(uint64_t leaf_count);

bool ec_plru_init(PLruTree *tree, uint64_t leaf_count, void *tree_head, ProcessContext *context);
void ec_plru_destroy(PLruTree *tree, ProcessContext *context);
void ec_plru_mark_active_path(PLruTree *plru, uint64_t leaf_index, ProcessContext *context);
int64_t ec_plru_find_inactive_leaf(PLruTree *plru, ProcessContext *context);
