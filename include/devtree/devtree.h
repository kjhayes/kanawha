#ifndef __KANAWHA_DEVTREE_DEVTREE_H__
#define __KANAWHA_DEVTREE_DEVTREE_H__

#include <kanawha/list.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/types.h>

#include <devtree/node.h>

struct devtree;
struct dt_driver;

#define DEVTREE_FLAG_UNFLATTENED (1ULL << 0)
#define DEVTREE_FLAG_PHYS_RESERVED (1ULL << 1)

struct devtree
{
    unsigned long flags;

    struct fdt *backing_data;
    size_t backing_size;

    ilist_node_t list_node;

    struct dt_node *root_node;

    struct ptree phandle_tree;
};

int
devtree_provide_fdt(struct fdt *fdt);

// Returns the first provided device tree
struct devtree *
devtree_get(void);

// Returns a virtual pointer to "dt's" backing fdt
struct fdt *
devtree_get_fdt(struct devtree *dt);

// Returns NULL if no node can be found
struct dt_node *
devtree_get_node_by_phandle(struct devtree *dt, fdt_phandle_t phandle);

#endif
