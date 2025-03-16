
#include <devtree/driver.h>

int
dt_driver_cannot_probe(
        struct dt_driver *driver,
        struct dt_node *node)
{
    return -EUNIMPL;
}
int
dt_driver_cannot_init_node(
        struct dt_driver *driver,
        struct dt_node *node)
{
    return -EUNIMPL;
}
int
dt_driver_cannot_deinit_node(
        struct dt_driver *driver,
        struct dt_node *node)
{
    return -EUNIMPL;
}
irq_t
dt_driver_cannot_xlate_irq(
        struct dt_driver *driver,
        struct dt_node *node,
        const fdt32_t *cells,
        size_t cell_count)
{
    return NULL_IRQ;
}

