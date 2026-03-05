#ifndef __KANAWHA__DEVTREE_NODE_H__
#define __KANAWHA__DEVTREE_NODE_H__

#include <devtree/types.h>
#include <kanawha/irq.h>
#include <kanawha/list.h>
#include <kanawha/pointer.h>
#include <kanawha/ptree.h>

#define DT_NODE_FLAG_MATCHED (1ULL << 0)

struct dt_node
{
    unsigned long flags;

    struct devtree *dt;
    struct fdt_node *backing_data;

    ilist_node_t global_node;

    struct dt_node *parent;
    ilist_t children;
    ilist_node_t child_node;

    struct dt_driver *driver;
    void *driver_state;
    ilist_node_t driver_node;

    // Phandle
    struct ptree_node phandle_node;

    // Formatted Name
    spinlock_t name_lock;
    char *name;
};

struct fdt_node *
dt_node_get_fdt_node(struct dt_node *node);

const char *
dt_node_get_name(struct dt_node *node);

// Read the property as a single u32
int
dt_node_read_property_u32(struct dt_node *node,
                          const char *prop_name,
                          uint32_t *val_out);

// Read the property as a single u64
int
dt_node_read_property_u64(struct dt_node *node,
                          const char *prop_name,
                          uint64_t *val_out);

// Tries reading the property as a single unsigned value
// (Allows for both 32-bit and 64-bit values)
int
dt_node_read_property_unsigned(struct dt_node *node,
                               const char *prop_name,
                               uintptr_t *val_out);

size_t
dt_node_reg_count(struct dt_node *node);

int
dt_node_read_reg(struct dt_node *node,
                 size_t buflen,
                 void __phys **reg_out,
                 size_t *size_out);

// Returns 0 if the device_type matches
int
dt_node_check_device_type(struct dt_node *node, const char *device_type);

int
dt_node_irq_count(struct dt_node *node, size_t *size_out);

int
dt_node_read_irq(struct dt_node *node, size_t index, irq_t *irq_out);

#endif
