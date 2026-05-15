#ifndef __KANAWHA__DEVTREE_DRIVER_H__
#define __KANAWHA__DEVTREE_DRIVER_H__

struct devtree;
struct dt_driver;
struct dt_node;

#include <devtree/match.h>
#include <devtree/types.h>
#include <kanawha/irq.h>
#include <kanawha/ops.h>

// Returns 0 if this driver can control the node
// (Assumes some ID has matched from the driver's ID list)
#define DT_DRIVER_PROBE_SIG(RET, ARG, ...)                                     \
    RET(int)                                                                   \
    ARG(struct dt_node *, node)

// Returns 0 on success
#define DT_DRIVER_INIT_NODE_SIG(RET, ARG, ...)                                 \
    RET(int)                                                                   \
    ARG(struct dt_node *, node)

#define DT_DRIVER_DEINIT_NODE_SIG(RET, ARG, ...)                               \
    RET(int)                                                                   \
    ARG(struct dt_node *, node)

#define DT_DRIVER_XLATE_IRQ(RET, ARG, ...)                                     \
    RET(irq_t)                                                                 \
    ARG(struct dt_node *, node)                                                \
    ARG(const fdt32_t *, cells)                                                \
    ARG(size_t, cell_count)

#define DT_DRIVER_XLATE_IRQ_MAP(RET, ARG, ...)                                 \
    RET(irq_t)                                                                 \
    ARG(struct dt_node *, node)                                                \
    ARG(const fdt32_t *, addr_cells)                                            \
    ARG(size_t, addr_cell_count) \
    ARG(const fdt32_t *, irq_cells)                                            \
    ARG(size_t, irq_cell_count)


#define DT_DRIVER_OP_LIST(OP, ...)                                             \
    OP(probe, DT_DRIVER_PROBE_SIG, ##__VA_ARGS__)                              \
    OP(init_node, DT_DRIVER_INIT_NODE_SIG, ##__VA_ARGS__)                      \
    OP(deinit_node, DT_DRIVER_DEINIT_NODE_SIG, ##__VA_ARGS__)                  \
    OP(xlate_irq, DT_DRIVER_XLATE_IRQ, ##__VA_ARGS__) \
    OP(xlate_irq_map, DT_DRIVER_XLATE_IRQ_MAP, ##__VA_ARGS__)

struct dt_driver_ops
{
    DECLARE_OP_LIST_PTRS(DT_DRIVER_OP_LIST, struct dt_driver *);
};

struct dt_driver
{
    ilist_node_t global_node;
    ilist_t devices;

    // Set By Driver Author
    struct dt_driver_ops *ops;
    size_t num_ids;
    struct dt_node_id *ids;
};

DEFINE_OP_LIST_WRAPPERS(DT_DRIVER_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        dt_driver,
                        OPS_STRUCT_PTR_ACCESSOR,
                        SELF_ACCESSOR)

#undef DT_DRIVER_PROBE_SIG
#undef DT_DRIVER_INIT_NODE_SIG
#undef DT_DRIVER_DEINIT_NODE_SIG
#undef DT_DRIVER_OP_LIST

// Default function implementations

// Always Return -EUNIMPL
int
dt_driver_cannot_probe(struct dt_driver *driver, struct dt_node *node);
// Always Return -EUNIMPL
int
dt_driver_cannot_init_node(struct dt_driver *driver, struct dt_node *node);
// Always Return -EUNIMPL
int
dt_driver_cannot_deinit_node(struct dt_driver *driver, struct dt_node *node);

// Always returns NULL_IRQ
irq_t
dt_driver_cannot_xlate_irq(struct dt_driver *driver,
                           struct dt_node *node,
                           const fdt32_t *cells,
                           size_t cell_count);
// Always returns NULL_IRQ
irq_t
dt_driver_cannot_xlate_irq_map(struct dt_driver *driver,
                           struct dt_node *node,
                           const fdt32_t *addr_cells,
                           size_t addr_cell_count,
                           const fdt32_t *irq_cells,
                           size_t irq_cell_count);

// Checks addr_cell_count == 0 and calls "dt_driver_xlate_irq".
irq_t
dt_driver_xlate_irq_map_no_address(
        struct dt_driver *driver,
        struct dt_node *node,
        const fdt32_t *addr_cells,
        size_t addr_cell_count,
        const fdt32_t *irq_cells,
        size_t irq_cell_count);

#endif
