
#include <devtree/driver.h>

irq_t
dt_driver_cannot_xlate_irq(
        struct dt_driver *driver,
        struct dt_node *node,
        const fdt32_t *cells,
        size_t cell_count)
{
    return NULL_IRQ;
}

