#ifndef __KANAWHA__STREE_H__
#define __KANAWHA__STREE_H__

/*
 * "String" Binary Search Tree
 */

struct stree {
    struct stree_node *root;
};

struct stree_node {
    struct stree_node *parent;
    struct stree_node *left;
    struct stree_node *right;
    const char *key;
};

int
stree_init(struct stree *tree);

// Keeps a reference to "str"
int stree_insert(
        struct stree *tree,
        struct stree_node *node);

// Returns the removed node (or NULL if the key doesn't exist)
struct stree_node *
stree_remove(
        struct stree *tree,
        const char *key);

// Returns NULL if the key doens't exist
struct stree_node *
stree_get(
        struct stree *tree,
        const char *key);

struct stree_node *
stree_get_first(struct stree *tree);

struct stree_node *
stree_get_next(struct stree_node *node);

#define DECLARE_STREE(__tree)\
    struct stree __tree = {\
        .root = NULL,\
    }

#endif
