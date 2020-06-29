#pragma once

#include <linux/rbtree.h>
#include "process-context.h"

typedef int (*cb_compare_callback)(void *left, void *right);
typedef void (*cb_free_callback)(void *data, ProcessContext *context);
typedef void (*cb_for_rbtree_node)(void *data, void *priv, ProcessContext *context);

typedef struct cb_tree {
    struct rb_root       root;
    bool                 valid;
    uint64_t             lock;
    atomic64_t           count;
    int                  key_offset;
    int                  node_offset;
    cb_compare_callback  compare;
    cb_free_callback     free;
} CB_RBTREE;

bool cb_rbtree_init(CB_RBTREE *tree,
                    int                  key_offset,
                    int                  node_offset,
                    cb_compare_callback  compare_cb,
                    cb_free_callback     free_cb,
                    ProcessContext *context);
void cb_rbtree_destroy(CB_RBTREE *tree, ProcessContext *context);

void *cb_rbtree_search(CB_RBTREE *tree, void *key, ProcessContext *context);
bool cb_rbtree_insert(CB_RBTREE *tree, void *data, ProcessContext *context);
bool cb_rbtree_delete_by_key(CB_RBTREE *tree, void *key, ProcessContext *context);
bool cb_rbtree_delete(CB_RBTREE *tree, void *data, ProcessContext *context);
void cb_rbtree_clear(CB_RBTREE *tree, ProcessContext *context);
void cb_rbtree_read_for_each(CB_RBTREE *tree, cb_for_rbtree_node callback, void *priv, ProcessContext *context);
void cb_rbtree_write_for_each(CB_RBTREE *tree, cb_for_rbtree_node callback, void *priv, ProcessContext *context);
