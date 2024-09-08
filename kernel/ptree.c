
#include <kanawha/ptree.h>
#include <kanawha/printk.h>
#include <kanawha/errno.h>
#include <kanawha/vmem.h>
#include <kanawha/assert.h>

static inline int
ptree_insert_bst(struct ptree *tree, struct ptree_node *node) 
{
    if(tree->root == NULL) {
        tree->root = node;
        node->parent = NULL;
    } else {
        int inserted = 0;
        struct ptree_node *potential_parent = tree->root;
        while (!inserted) {
          if(potential_parent->key > node->key) {
              if(potential_parent->left == NULL) {
                  node->parent = potential_parent;
                  potential_parent->left = node;
                  inserted = 1;
              } else {
                  potential_parent = potential_parent->left;
              }
          } else if(potential_parent->key < node->key) {
              if(potential_parent->right == NULL) {
                  node->parent = potential_parent;
                  potential_parent->right = node;
                  inserted = 1;
              } else {
                  potential_parent = potential_parent->right;
              }
          } else {
              // This key is already in the tree
              return -EEXIST;
          }
        }
    }

    return 0;
}

static int
ptree_rebalance(struct ptree *tree) {
    // Just don't rebalance for now
    // (Inefficient but should still be "correct")
    return 0;
}

void
ptree_init(struct ptree *tree) {
    tree->root = NULL;
}

int
ptree_insert(struct ptree *tree, struct ptree_node *node, uintptr_t key) 
{
    int res;

    node->key = key;
    node->left = NULL;
    node->right = NULL;
    res = ptree_insert_bst(tree, node);
    if(res) {
        return res;
    }
    res = ptree_rebalance(tree);
    if(res) {
        return res;
    }
    return 0;
}

int
ptree_insert_any(
        struct ptree *tree,
        struct ptree_node *node)
{
    uintptr_t key = 0;

    node->left = NULL;
    node->right = NULL;

    struct ptree_node *other =
        ptree_get_last(tree);
    if(other == NULL) {
        key = 0;
    } else if(other->key != ~(uintptr_t)(0)) {
        key = other->key + 1;
    } else {
        do {
            uintptr_t original_key = other->key;
            if(original_key == 0) {
                // We would have iterated over
                // 2^63 allocated keys if we reach here
                return -ENOMEM;
            }
            other = ptree_get_max_less(tree, other->key-1);
            if(other == NULL) {
                key = 0;
                break;
            }
            else if(other->key == original_key - 1) {
                continue;
            }
            else {
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
    if(node == NULL) {
        return node;
    }

    struct ptree_node *left = node->left;
    struct ptree_node *right = node->right;

    if(node == tree->root) {
        tree->root = NULL;
    } else if(node->parent != NULL) {
        if(node->parent->left == node) {
            node->parent->left = NULL;
        } else if(node->parent->right == node) {
            node->parent->right = NULL;
        } else {
            // This shouldn't be possible
            eprintk("ptree Node has parent, but isn't child of parent!\n");
            // Continue anyways
        }
    } else {
        // This shouldn't be possible
        eprintk("ptree Node has parent, but isn't child of parent!\n");
        // Continue...
    }

    // We've fully removed our node (and it's subtree) from the main tree

    // Trim and re-insert the left and right subtrees if they exist
    if(left != NULL) {
        // (This isn't really necessary but let's be safe)
        left->parent = NULL;

        // Don't do rebalancing yet
        res = ptree_insert_bst(tree, left);
        if(res) {
            // There's nothing we can really do, 
            // but leave the subtree attached to our node
            // so it's not lost entirely
        } else {
            node->left = NULL;
        }
    }
    // Do the same as above for the right subtree
    if(right != NULL) {
        right->parent = NULL;

        res = ptree_insert_bst(tree, right);
        if(res) {
        } else {
            node->right = NULL;
        }
    }

    res = ptree_rebalance(tree);
    if(res) {
        // Hmmmmmmm weird, not much we can do about it here though
        // (Hopefully it's not too bad and will get fixed on the next
        //  attempt to rebalance)
    }

    return node;
}

struct ptree_node *
ptree_get(struct ptree *tree, uintptr_t key)
{
    dprintk("ptree_get key=%p\n", key);
    struct ptree_node *current = tree->root;
    while(current != NULL) {
        DEBUG_ASSERT(KERNEL_ADDR(current));
        dprintk("cmp=%p\n", current->key);
        if(current->key < key) {
            dprintk("go right\n");
            current = current->right;
        }
        else if(current->key > key) {
            dprintk("go left\n");
            current = current->left;
        }
        else { // current->key == key
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
    while(current != NULL) {
        if(current->key < key) {
            if(current_max == NULL || (current_max->key < current->key)) {
                current_max = current;
            }
            if(current->right) {
                current = current->right;
            } else {
                break;
            }
        } else { // current->key >= key
            if(current->left) {
                current = current->left;
            } else {
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
    dprintk("ptree_get_max_less_or_eq(tree=%p,key=%p)\n",tree,key);
    while(current != NULL) {
        if(current->key < key) {
            if(current_max == NULL || (current_max->key < current->key)) {
                current_max = current;
            }
            dprintk("go right from key=%p\n", current->key);
            current = current->right;
            continue;
        } else { // current->key >= key
            if(current->key == key) {
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
ptree_get_first(struct ptree *tree)
{
    struct ptree_node *least = tree->root;
    if(least == NULL) {
        return least;
    }

    while(least->left != NULL) { least = least->left; }

    return least;
}

struct ptree_node *
ptree_get_last(struct ptree *tree)
{
    struct ptree_node *greatest = tree->root;
    if(greatest == NULL) {
        return greatest;
    }

    while(greatest->right != NULL) { greatest = greatest->right; }

    return greatest;
}

struct ptree_node *
ptree_get_next(struct ptree_node *node)
{
    if(node->right) {
        return node->right;
    }

    struct ptree_node *parent = node->parent;

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

struct ptree_node *
ptree_get_prev(struct ptree_node *node)
{
    if(node->left) {
        return node->left;
    }

    struct ptree_node *parent;

    while(parent) {
        if(parent->right == node) {
            return parent;
        } else {
            node = parent;
            parent = parent->parent;
        }
    }

    return NULL;
}

static inline void
ptree_subtree_for_each(
        struct ptree_node *subtree,
        ptree_visitor_f *func,
        void *state)
{
    if(subtree == NULL) {
        return;
    }
    if(subtree->left != NULL) {
        ptree_subtree_for_each(
                subtree->left,
                func,
                state);
    }
    (*func)(subtree, state);
    if(subtree->right != NULL) {
        ptree_subtree_for_each(
                subtree->right,
                func,
                state);
    }
}

void ptree_for_each(
        struct ptree *tree,
        ptree_visitor_f *func,
        void *state) 
{
    ptree_subtree_for_each(tree->root, func, state);
}

