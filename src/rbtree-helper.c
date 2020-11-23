// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "rbtree-helper.h"
#include "cb-spinlock.h"
#include "priv.h"

static struct rb_node *_get_left_most_node(struct rb_node *node);

static bool __cb_rbtree_delete_locked(CB_RBTREE *tree, void *data, ProcessContext *context);
static bool __is_valid_tree(CB_RBTREE *tree);
static void __rbtree_for_each_locked(CB_RBTREE *tree, cb_for_rbtree_node callback, void *priv, ProcessContext *context);

#define get_data_ptr(tree, ptr)  ((void *)((ptr) - (tree)->node_offset))
#define get_node_ptr(tree, ptr)  ((struct rb_node *)((ptr) + (tree)->node_offset))
#define get_key_ptr(tree, ptr)   ((void *)((ptr) + (tree)->key_offset))

static bool __is_valid_tree(CB_RBTREE *tree)
{
    return (tree && tree->valid);
}

bool cb_rbtree_init(CB_RBTREE *tree,
                    int                  key_offset,
                    int                  node_offset,
                    cb_compare_callback  compare_cb,
                    cb_free_callback     free_cb,
                    cb_copy_callback     copy_cb,
                    ProcessContext *context)
{
    if (tree && compare_cb && free_cb)
    {
        tree->root        = RB_ROOT;
        tree->valid       = true;
        tree->key_offset  = key_offset;
        tree->node_offset = node_offset;
        tree->compare     = compare_cb;
        tree->free        = free_cb;
        tree->copy_cb     = copy_cb;
        cb_spinlock_init(&tree->lock, context);
        atomic64_set(&tree->count, 0);
        return true;
    }

    return false;
}

void cb_rbtree_destroy(CB_RBTREE *tree, ProcessContext *context)
{
    if (__is_valid_tree(tree))
    {
        cb_rbtree_clear(tree, context);
        tree->valid   = false;
        tree->root    = RB_ROOT;
        tree->compare = NULL;
        tree->free    = NULL;
        cb_spinlock_destroy(&tree->lock, context);
        atomic64_set(&tree->count, 0);
    }
}

static void *cb_rbtree_search_locked(CB_RBTREE *tree, void *key);

void *cb_rbtree_search(CB_RBTREE *tree, void *key, ProcessContext *context)
{
    void *data = NULL;

    if (__is_valid_tree(tree) && key)
    {
        cb_read_lock(&tree->lock, context);
        data = cb_rbtree_search_locked(tree, key);
        cb_read_unlock(&tree->lock, context);
    }

    return data;
}

static void *cb_rbtree_search_locked(CB_RBTREE *tree, void *key)
{
    void *return_data = NULL;
    struct rb_node *node = NULL;

    if (__is_valid_tree(tree) && key)
    {
        node = tree->root.rb_node;
        while (node)
        {
            void *data     = get_data_ptr(tree, node);
            void *node_key = get_key_ptr(tree, data);
            int   result   = tree->compare(key, node_key);

            if (result == -1)
            {
                node = node->rb_left;
            } else if (result == 1)
            {
                node = node->rb_right;
            } else if (result == 0)
            {
                return_data = data;
                break;
            } else
            {
                break;
            }
        }
    }

    return return_data;
}

bool cb_rbtree_insert(CB_RBTREE *tree, void *new_data, ProcessContext *context)
{
    bool             didInsert    = false;
    struct rb_node **insert_point = NULL;
    struct rb_node *parent       = NULL;

    if (__is_valid_tree(tree) && new_data)
    {
        void *new_key  = NULL;
        void *new_node = NULL;

        cb_write_lock(&tree->lock, context);
        new_key  = get_key_ptr(tree, new_data);
        new_node = get_node_ptr(tree, new_data);

        // Figure out where to insert the new data
        //  This finds the location of the pointer where the new node needs to
        //  be grafted.
        insert_point = &(tree->root.rb_node);
        while (*insert_point)
        {
            void *current_data = get_data_ptr(tree, *insert_point);
            void *current_key  = get_key_ptr(tree, current_data);
            int   result       = tree->compare(new_key, current_key);

            parent = *insert_point;
            if (result == -1)
            {
                insert_point = &((*insert_point)->rb_left);
            } else if (result == 1)
            {
                insert_point = &((*insert_point)->rb_right);
            } else
            {
                insert_point = NULL;
                parent       = NULL;
                break;
            }
        }

        if (insert_point)
        {
            // Link the node to its parent and then rebalance the tree
            rb_link_node(new_node, parent, insert_point);
            rb_insert_color(new_node, &(tree->root));
            atomic64_inc(&tree->count);

            didInsert = true;
        }
        cb_write_unlock(&tree->lock, context);
    }

    return didInsert;
}

bool cb_rbtree_update(CB_RBTREE *tree, void *key, void *src_data, ProcessContext *context)
{
    bool didUpdate = false;

    if (__is_valid_tree(tree) && tree->copy_cb && src_data)
    {
        void *data = NULL;

        cb_write_lock(&tree->lock, context);

        data = cb_rbtree_search_locked(tree, key);

        if (data)
        {
            tree->copy_cb(data, src_data);
            didUpdate = true;
        }

        cb_write_unlock(&tree->lock, context);
    }

    return didUpdate;
}

bool cb_rbtree_delete_by_key(CB_RBTREE *tree, void *key, ProcessContext *context)
{
    bool didDelete = false;

    if (__is_valid_tree(tree))
    {
        void *data = NULL;

        cb_write_lock(&tree->lock, context);

        data = cb_rbtree_search_locked(tree, key);
        didDelete = __cb_rbtree_delete_locked(tree, data, context);

        cb_write_unlock(&tree->lock, context);
    }

    return didDelete;
}

bool cb_rbtree_delete(CB_RBTREE *tree, void *data, ProcessContext *context)
{
    bool didDelete = false;

    if (__is_valid_tree(tree))
    {
        cb_write_lock(&tree->lock, context);

        didDelete = __cb_rbtree_delete_locked(tree, data, context);

        cb_write_unlock(&tree->lock, context);
    }

    return didDelete;
}

static bool __cb_rbtree_delete_locked(CB_RBTREE *tree, void *data, ProcessContext *context)
{
    bool didDelete = false;

    if (__is_valid_tree(tree) && data)
    {
        struct rb_node *node = get_node_ptr(tree, data);

        if (!RB_EMPTY_NODE(node))
        {
            rb_erase(node, &tree->root);
            ATOMIC64_DEC__CHECK_NEG(&tree->count);

            didDelete = true;
        }
        tree->free(data, context);
    }

    return didDelete;
}

void cb_rbtree_read_for_each(CB_RBTREE *tree, cb_for_rbtree_node callback, void *priv, ProcessContext *context)
{
    if (__is_valid_tree(tree) && callback)
    {
        cb_read_lock(&tree->lock, context);
        __rbtree_for_each_locked(tree, callback, priv, context);
        cb_read_unlock(&tree->lock, context);
    }
}

void cb_rbtree_write_for_each(CB_RBTREE *tree, cb_for_rbtree_node callback, void *priv, ProcessContext *context)
{
    if (__is_valid_tree(tree) && callback)
    {
        cb_write_lock(&tree->lock, context);
        __rbtree_for_each_locked(tree, callback, priv, context);
        cb_write_unlock(&tree->lock, context);
    }
}

static void __rbtree_for_each_locked(CB_RBTREE *tree, cb_for_rbtree_node callback, void *priv, ProcessContext *context)
{
    struct rb_node *node;

    for (node = rb_first(&tree->root); node; node = rb_next(node))
    {
        callback(get_data_ptr(tree, node), priv, context);
    }
}

static void __rotate_child(struct rb_node *node)
{
    node->rb_left  = node->rb_right;
    node->rb_right = NULL;
}

void cb_rbtree_clear(CB_RBTREE *tree, ProcessContext *context)
{
    struct rb_node *node;
    uint64_t count = 0;

    if (__is_valid_tree(tree))
    {
        // Start with the left most node.  Delete that and walk our way back up.
        //  The logic moves the right brach to the left and keeps walking left.
        cb_write_lock(&tree->lock, context);
        node = _get_left_most_node(tree->root.rb_node);
        while (node)
        {
            if (node->rb_right)
            {
                // This node has a right child so we can not delete it yet
                //  Make it this nodes left child, and re-discover the left most
                //  child.
                __rotate_child(node);
                node = _get_left_most_node(node);
            } else
            {
                // Get the `data` pointer from the current node
                void *data = get_data_ptr(tree, node);

                // Move the current node pointer to the parent of what we are
                //  about to delete.  If this is not null, clear the left child
                //  because we are deleting it now.
                node = rb_parent(node);
                if (node)
                {
                    node->rb_left = NULL;
                }

                // Decrement the counter and delete the node
                ATOMIC64_DEC__CHECK_NEG(&tree->count);
                tree->free(data, context);
            }
        }

        count = atomic64_read(&tree->count);
        if (count != 0)
        {
            TRACE(DL_ERROR, "CB_RBTREE still has %lld elements after being cleared!", count);
        }

        tree->root = RB_ROOT;
        cb_write_unlock(&tree->lock, context);
    }
}

static struct rb_node *_get_left_most_node(struct rb_node *node)
{
    if (node)
    {
        while (node->rb_left)
        {
            node = node->rb_left;
        }
    }

    return node;
}
