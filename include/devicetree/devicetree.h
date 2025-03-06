#ifndef __KANAWHA_DEVICETREE_DEVICETREE_H__
#define __KANAWHA_DEVICETREE_DEVICETREE_H__

#include <kanawha/types.h>
#include <kanawha/pointer.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>

#define DEVICETREE_FLAG_UNFLATTENED (1ULL<<0)

struct device_tree
{
    unsigned long flags;

    struct fdt __phys *backing_data;
    size_t backing_size;

    ilist_node_t list_node;
};

int
devicetree_provide_dtb(
        struct fdt __phys *dtb);

// Returns the first provided device tree
struct device_tree *
devicetree_get(void);

// Returns a virtual pointer to "dt's" backing fdt
struct fdt *
devicetree_get_fdt(
        struct device_tree *dt);

#endif
