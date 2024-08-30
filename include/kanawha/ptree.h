#ifndef __KANAWHA__PTREE_H__
#define __KANAWHA__PTREE_H__

#include <kanawha/printk.h>

/*
 * "Pointer" Binary Search Tree, indexed on uintptr_t
 */

#include <kanawha/stdint.h>

struct ptree {
    struct ptree_node *root;
};

struct ptree_node {
    struct ptree_node *parent;
    struct ptree_node *left;
    struct ptree_node *right;
    uintptr_t key;
};

void ptree_init(struct ptree *tree);

// All operations on ptree's assume locking is done externally

// Returns 0 on success, 1 on failure
int ptree_insert(struct ptree *tree, struct ptree_node *node, uintptr_t key);

// Tries to insert the node with any free key
//
// This should be able to fill up the tree (2^64 entries)
// but assumes most insertions use ptree_insert_any or
// a specific key <<< 2^64
//
// Returns 0 on success, errno on failure
int ptree_insert_any(
        struct ptree *tree,
        struct ptree_node *node);

// Returns NULL if the key doesn't exist, and the removed node if it does
struct ptree_node * ptree_remove(struct ptree *tree, uintptr_t key);

// Returns NULL if the key doesn't exist
struct ptree_node * ptree_get(struct ptree *tree, uintptr_t key);

// Non-inclusive
struct ptree_node * ptree_get_max_less(struct ptree *tree, uintptr_t key);

// Inclusive
struct ptree_node *ptree_get_max_less_or_eq(struct ptree *tree, uintptr_t key);

// "First" is the node with the least key
struct ptree_node * ptree_get_first(struct ptree *tree);
// "Last" is the node with the greatest key
struct ptree_node * ptree_get_last(struct ptree *tree);
// "Next" is the closest node with greater key
struct ptree_node * ptree_get_next(struct ptree_node *node);
// "Prev" is the closest node with lesser key
struct ptree_node * ptree_get_prev(struct ptree_node *node);

typedef void(ptree_visitor_f)(struct ptree_node *, void *);
void ptree_for_each(struct ptree *tree, ptree_visitor_f *func, void *state);

static inline void
ptree_dump_visitor(
        struct ptree_node *node,
        void *state)
{
    printk_f *printer = state;
    (*printer)("%p\n", (uintptr_t)node->key);
}

static inline void
ptree_dump(printk_f *printer, struct ptree *tree)
{
    ptree_for_each(tree, ptree_dump_visitor, printer);
}

#define DECLARE_PTREE(__tree)\
    struct ptree __tree = {\
        .root = NULL\
    }

#endif
