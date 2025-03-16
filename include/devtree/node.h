#ifndef __KANAWHA__DEVTREE_NODE_H__
#define __KANAWHA__DEVTREE_NODE_H__

#include <kanawha/list.h>
#include <kanawha/pointer.h>
#include <kanawha/ptree.h>
#include <kanawha/irq.h>
#include <devtree/types.h>

#define DT_NODE_FLAG_MATCHED (1ULL<<0)

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
};

struct fdt_node *
dt_node_get_fdt_node(
        struct dt_node *node);

int
dt_node_read_property_u32(
        struct dt_node *node,
        const char *prop_name,
        uint32_t *val_out);

size_t
dt_node_reg_count(
        struct dt_node *node);

int
dt_node_read_reg(
        struct dt_node *node,
        size_t index,
        void __phys **reg_out,
        size_t *size_out);

// Returns 0 if the device_type matches
int
dt_node_check_device_type(
        struct dt_node *node,
        const char *device_type);

int
dt_node_irq_count(
        struct dt_node *node,
        size_t *size_out);

int
dt_node_read_irq(
        struct dt_node *node,
        size_t index,
        irq_t *irq_out);

#endif
