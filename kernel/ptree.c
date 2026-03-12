
#include <kanawha/assert.h>
#include <kanawha/errno.h>
#include <kanawha/printk.h>
#include <kanawha/ptree.h>
#include <kanawha/vmem.h>

static inline int
ptree_insert_bst(struct ptree *tree, struct ptree_node *node)
{
    if(tree->root == NULL)
    {
        tree->root = node;
        node->parent = NULL;
        return 0;
    }
    else
    {
        struct ptree_node *potential_parent = tree->root;
        while(1)
        {
            if(potential_parent->key > node->key)
            {
                if(potential_parent->left == NULL)
                {
                    node->parent = potential_parent;
                    potential_parent->left = node;
                    return 0;
                }
                else
                {
                    potential_parent = potential_parent->left;
                }
            }
            else if(potential_parent->key < node->key)
            {
                if(potential_parent->right == NULL)
                {
                    node->parent = potential_parent;
                    potential_parent->right = node;
                    return 0;
                }
                else
                {
                    potential_parent = potential_parent->right;
                }
            }
            else
            {
                // This key is already in the tree
                return -EEXIST;
            }
        }
    }
}

void
ptree_init(struct ptree *tree)
{
    tree->root = NULL;
}

static void
ptree_solve_red_red_conflict(
        struct ptree *tree,
        struct ptree_node *bottom)
{
    struct ptree_node *parent;
    struct ptree_node *uncle;
    unsigned int uncle_color;

recurse:
    parent = bottom->parent;
    uncle = NULL;
    if(parent) {
        uncle = parent->left == bottom ? parent->right : parent->left;
    }
    if(uncle == NULL) {
        uncle_color = PTREE_COLOR_BLACK;
    }

    DEBUG_ASSERT(bottom->color == PTREE_COLOR_RED);
    DEBUG_ASSERT(parent == NULL || bottom->parent->color == PTREE_COLOR_RED);

    if(uncle_color == PTREE_COLOR_RED) {
        // Uncle is red (so it is not NULL)
        // Recolor both child nodes to black
        // and the parent to red
        uncle->color = PTREE_COLOR_BLACK;
        bottom->color = PTREE_COLOR_BLACK;
        parent->color = PTREE_COLOR_RED;

        if(parent->parent) {
            bottom = parent;
            goto recurse;
        } else {
            // Recolor the root to fix the conflict
            parent->color = PTREE_COLOR_BLACK;
        }
    } else { // uncle_color == PTREE_COLOR_BLACK
        // TODO
        // Not correctly rebalancing is a performance
        // but not a correctness issue
    }
}

int
ptree_insert(struct ptree *tree, struct ptree_node *node, uintptr_t key)
{
    int res;

    node->key = key;
    node->left = NULL;
    node->right = NULL;

    node->color = PTREE_COLOR_RED;

    res = ptree_insert_bst(tree, node);
    if(res)
    {
        return res;
    }

    if(node->parent == NULL) {
        // We are the root node
        node->color = PTREE_COLOR_BLACK;
        return 0;
    }
    else if(node->parent->color == PTREE_COLOR_BLACK) {
        // We inserted a red node and ended up
        // the child of a black node, so no
        // invariant has been violated.
        return 0;
    } else {
        // We have a "red-red" conflict
        ptree_solve_red_red_conflict(tree, node);
    }

    return 0;
}

int
ptree_insert_any(struct ptree *tree, struct ptree_node *node)
{
    uintptr_t key = 0;

    node->left = NULL;
    node->right = NULL;

    struct ptree_node *other = ptree_get_last(tree);
    if(other == NULL)
    {
        key = 0;
    }
    else if(other->key != ~(uintptr_t)(0))
    {
        key = other->key + 1;
    }
    else
    {
        do
        {
            uintptr_t original_key = other->key;
            if(original_key == 0)
            {
                // We would have iterated over
                // 2^63 allocated keys if we reach here
                return -ENOMEM;
            }
            other = ptree_get_max_less(tree, other->key - 1);
            if(other == NULL)
            {
                key = 0;
                break;
            }
            else if(other->key == original_key - 1)
            {
                continue;
            }
            else
            {
                key = other->key + 1;
                break;
            }
        } while(1);
    }

    // "key" should be a free key now
    node->key = key;
    return ptree_insert(tree, node, key);
}

struct ptree_node *
ptree_remove(struct ptree *tree, uintptr_t key)
{
    int res;

    struct ptree_node *node = ptree_get(tree, key);
    if(node == NULL)
    {
        return node;
    }

    struct ptree_node *parent = node->parent;
    struct ptree_node *left = node->left;
    struct ptree_node *right = node->right;

    struct ptree_node **parent_slot;
    if(node == tree->root)
    {
        parent_slot = &tree->root;
    }
    else if(node->parent != NULL)
    {
        if(node->parent->left == node)
        {
            parent_slot = &node->parent->left;
        }
        else if(node->parent->right == node)
        {
            parent_slot = &node->parent->right;
        }
        else
        {
            // This shouldn't be possible
            panic("ptree node has parent, but isn't child of parent!\n");
            // Continue anyways
        }
    }
    else
    {
        // This shouldn't be possible
        panic("ptree node has parent, but isn't child of parent!\n");
        // Continue...
    }

    *parent_slot = NULL;

    // We've fully removed our node (and it's subtree) from the main tree

    // Trim and re-insert the left and right subtrees if they exist
    if(left == NULL)
    {
        if(right != NULL)
        {
            // We can just replace the node with the right subtree
            *parent_slot = right;
            right->parent = parent;
        }
    }
    else
    {
        if(right != NULL)
        {
            // Both left and right exist...
            left->parent = NULL;
            right->parent = NULL;
            ptree_insert_bst(tree, left);
            ptree_insert_bst(tree, right);
        }
        else
        {
            // We can just replace the node with the left subtree
            *parent_slot = left;
            left->parent = parent;
        }
    }

    return node;
}

struct ptree_node *
ptree_get(struct ptree *tree, uintptr_t key)
{
    dprintk("ptree_get key=%p\n", key);
    struct ptree_node *current = tree->root;
    while(current != NULL)
    {
        DEBUG_ASSERT(KERNEL_ADDR(current));
        dprintk("cmp=%p\n", current->key);
        if(current->key < key)
        {
            dprintk("go right\n");
            current = current->right;
        }
        else if(current->key > key)
        {
            dprintk("go left\n");
            current = current->left;
        }
        else
        { // current->key == key
            dprintk("found\n");
            return current;
        }
    }
    dprintk("failed\n");
    return NULL;
}

struct ptree_node *
ptree_get_max_less(struct ptree *tree, uintptr_t key)
{
    struct ptree_node *current_max = NULL;
    struct ptree_node *current = tree->root;
    while(current != NULL)
    {
        if(current->key < key)
        {
            if(current_max == NULL || (current_max->key < current->key))
            {
                current_max = current;
            }
            if(current->right)
            {
                current = current->right;
            }
            else
            {
                break;
            }
        }
        else
        { // current->key >= key
            if(current->left)
            {
                current = current->left;
            }
            else
            {
                break;
            }
        }
    }
    return current_max;
}

struct ptree_node *
ptree_get_max_less_or_eq(struct ptree *tree, uintptr_t key)
{
    struct ptree_node *current_max = NULL;
    struct ptree_node *current = tree->root;
    dprintk("ptree_get_max_less_or_eq(tree=%p,key=%p)\n", tree, key);
    while(current != NULL)
    {
        if(current->key < key)
        {
            if(current_max == NULL || (current_max->key < current->key))
            {
                current_max = current;
            }
            dprintk("go right from key=%p\n", current->key);
            current = current->right;
            continue;
        }
        else
        { // current->key >= key
            if(current->key == key)
            {
                dprintk("returning exact %p\n", current);
                return current;
            }
            dprintk("go left from key=%p\n", current->key);
            current = current->left;
            continue;
        }
    }
    dprintk("returning %p\n", current_max);
    return current_max;
}

struct ptree_node *
ptree_get_min_greater(struct ptree *tree, uintptr_t key)
{
    struct ptree_node *current_min = NULL;
    struct ptree_node *current = tree->root;
    while(current != NULL)
    {
        if(current->key > key)
        {
            if(current_min == NULL || current_min->key > current->key)
            {
                current_min = current;
            }
            current = current->left;
            continue;
        }
        else
        { // Current key is too small
            current = current->right;
            continue;
        }
    }

    return current_min;
}

struct ptree_node *
ptree_get_min_greater_or_eq(struct ptree *tree, uintptr_t key)
{
    struct ptree_node *current_min = NULL;
    struct ptree_node *current = tree->root;
    while(current != NULL)
    {
        if(current->key > key)
        {
            if(current_min == NULL || current_min->key > current->key)
            {
                current_min = current;
            }
            current = current->left;
            continue;
        }
        else
        { // Current key is too small
            if(current->key == key)
            {
                return current;
            }
            current = current->right;
            continue;
        }
    }
    return current_min;
}

struct ptree_node *
ptree_get_first(struct ptree *tree)
{
    struct ptree_node *least = tree->root;
    if(least == NULL)
    {
        return least;
    }

    while(least->left != NULL)
    {
        least = least->left;
    }

    return least;
}

struct ptree_node *
ptree_get_last(struct ptree *tree)
{
    struct ptree_node *greatest = tree->root;
    if(greatest == NULL)
    {
        return greatest;
    }

    while(greatest->right != NULL)
    {
        greatest = greatest->right;
    }

    return greatest;
}

struct ptree_node *
ptree_get_next(struct ptree_node *node)
{
    DEBUG_ASSERT(KERNEL_ADDR(node));
    if(node->right)
    {
        DEBUG_ASSERT(KERNEL_ADDR(node->right));
        struct ptree_node *right = node->right;
        // Go as far left as possible after going right once
        while(right->left)
        {
            right = right->left;
            DEBUG_ASSERT(KERNEL_ADDR(right));
        }
        return right;
    }

    struct ptree_node *parent;
    parent = node->parent;
    while(parent != NULL)
    {
        DEBUG_ASSERT(KERNEL_ADDR(parent));
        if(parent->left == node)
        {
            // parent is next greater
            return parent;
        }
        else
        {
            // parent is lesser
            node = parent;
            parent = parent->parent;
            continue;
        }
    }

    return NULL;
}

struct ptree_node *
ptree_get_prev(struct ptree_node *node)
{
    if(node->left)
    {
        return node->left;
    }

    struct ptree_node *parent = node->parent;

    while(parent)
    {
        if(parent->right == node)
        {
            return parent;
        }
        else
        {
            node = parent;
            parent = parent->parent;
        }
    }

    return NULL;
}

static inline void
ptree_subtree_for_each(struct ptree_node *subtree,
                       ptree_visitor_f *func,
                       void *state)
{
    if(subtree == NULL)
    {
        return;
    }
    if(subtree->left != NULL)
    {
        DEBUG_ASSERT(subtree->left != subtree);
        ptree_subtree_for_each(subtree->left, func, state);
    }
    (*func)(subtree, state);
    if(subtree->right != NULL)
    {
        DEBUG_ASSERT(subtree->right != subtree);
        ptree_subtree_for_each(subtree->right, func, state);
    }
}

void
ptree_for_each(struct ptree *tree, ptree_visitor_f *func, void *state)
{
    ptree_subtree_for_each(tree->root, func, state);
}
