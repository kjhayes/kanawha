
#include <kanawha/stree.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/errno.h>
#include <kanawha/printk.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>

static int
stree_insert_bst(
        struct stree *tree,
        struct stree_node *node)
{
    DEBUG_ASSERT(KERNEL_ADDR(tree));
    DEBUG_ASSERT(KERNEL_ADDR(node));
    if(tree->root == NULL) {
        tree->root = node;
        node->parent = NULL;
        return 0;
    }

    struct stree_node *parent = tree->root;
    while(parent != NULL) {
        int cmp = strcmp(node->key, parent->key);
        if(cmp < 0) {
            if(parent->left == NULL) {
                parent->left = node;
                node->parent = parent;
                break;
            } else {
                parent = parent->left;
            }
        } else if(cmp > 0) {
            if(parent->right == NULL) {
                parent->right = node;
                node->parent = parent;
                break;
            } else {
                parent = parent->right;
            }
        } else {
            return -EEXIST;
        }
    }
    return 0;
}

static int
stree_rebalance(struct stree *tree)
{
    // TODO
    return 0;
}

int
stree_init(struct stree *tree) {
    tree->root = NULL;
    return 0;
}

int stree_insert(
        struct stree *tree,
        struct stree_node *node)
{
    int res;
    res = stree_insert_bst(tree, node);
    if(res) {return res;}
    res = stree_rebalance(tree);
    if(res) {return res;}
    return 0;
}

struct stree_node *
stree_remove(
        struct stree *tree,
        const char *key)
{
    dprintk("stree_remove: getting node\n");
    struct stree_node *node = stree_get(tree, key);
    if(node == NULL) {
        return node;
    } 

    dprintk("stree_remove: deattaching node\n");
    struct stree_node *parent = node->parent;
    if(parent == NULL) {
        DEBUG_ASSERT(tree->root == node);
        tree->root = NULL;
    } else {
        if(parent->left == node) {
            parent->left = NULL;
        } else if(parent->right == node) {
            parent->right = NULL;
        } else {
            eprintk("stree_remove found malformed stree!\n");
            return NULL;
        }
    }

    dprintk("stree_remove: reattaching left\n");
    int res;
    if(node->left) {
        node->left->parent = NULL;
        res = stree_insert_bst(tree, node->left);
        if(res) {
            eprintk("Failed to insert node left branch in stree_remove!\n");
            return NULL;
        }
        node->left = NULL;
    }
    dprintk("stree_remove: reattaching right\n");
    if(node->right) {
        node->right->parent = NULL;
        res = stree_insert_bst(tree, node->right);
        if(res) {
            eprintk("Failed to insert node right branch in stree_remove!\n");
            return NULL;
        }
        node->right = NULL;
    }

    dprintk("stree_remove: rebalancing\n");
    res = stree_rebalance(tree);
    if(res) {
        eprintk("Failed to rebalance stree after stree_remove!\n");

        // We still removed node even if the tree is imbalanced
        return node;
    }

    return node;
}

struct stree_node *
stree_get(
        struct stree *tree,
        const char *key)
{
    dprintk("stree_get(key=\"%s\")\n", key);

    struct stree_node *cur = tree->root;
    while(cur != NULL) {
        int cmp = strcmp(key, cur->key);
        dprintk("cmp=\"%s\"\n", cur->key);
        if(cmp > 0) {
            dprintk("go right\n");
            cur = cur->right;
        } else if(cmp < 0) {
            dprintk("go left\n");
            cur = cur->left;
        } else {
            dprintk("found\n");
            return cur;
        }
    }
    dprintk("failed\n");
    return NULL;
}

struct stree_node *
stree_get_first(struct stree *tree)
{
    struct stree_node *cur = tree->root;
    while(cur != NULL && cur->left != NULL) {
        cur = cur->left;
    }
    return cur;
}

struct stree_node *
stree_get_next(struct stree_node *node)
{
    if(node->right) {
        struct stree_node *right = node->right;
        while(right->left) {
            right = right->left;
        }
        return right;
    }

    struct stree_node *parent = node->parent;

    while(parent) {
        if(parent->left == node) {
            return parent;
        } else { // parent->right == node
            node = parent;
            parent = parent->parent;
        }
    }

    return NULL;
}

