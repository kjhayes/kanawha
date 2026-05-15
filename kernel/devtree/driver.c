
#include <devtree/driver.h>

int
dt_driver_cannot_probe(struct dt_driver *driver, struct dt_node *node)
{
    return -EUNIMPL;
}
int
dt_driver_cannot_init_node(struct dt_driver *driver, struct dt_node *node)
{
    return -EUNIMPL;
}
int
dt_driver_cannot_deinit_node(struct dt_driver *driver, struct dt_node *node)
{
    return -EUNIMPL;
}
irq_t
dt_driver_cannot_xlate_irq(struct dt_driver *driver,
                           struct dt_node *node,
                           const fdt32_t *cells,
                           size_t cell_count)
{
    return NULL_IRQ;
}

irq_t
dt_driver_cannot_xlate_irq_map(struct dt_driver *driver,
                           struct dt_node *node,
                           const fdt32_t *addr_cells,
                           size_t addr_cell_count,
                           const fdt32_t *irq_cells,
                           size_t irq_cell_count)
{
    printk("dt_driver_cannot_xlate_irq_map!\n");
    return NULL_IRQ;
}

irq_t
dt_driver_xlate_irq_map_no_address(
        struct dt_driver *driver,
        struct dt_node *node,
        const fdt32_t *addr_cells,
        size_t addr_cell_count,
        const fdt32_t *irq_cells,
        size_t irq_cell_count)
{
    if(addr_cell_count != 0) {
        wprintk("dt_driver_xlate_irq_map_no_address: #address-cells=%lu!\n", addr_cell_count);
        return NULL_IRQ;
    }
    return dt_driver_xlate_irq(
            driver,
            node,
            irq_cells,
            irq_cell_count);
}
