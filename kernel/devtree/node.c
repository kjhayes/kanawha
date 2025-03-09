
#include <devtree/node.h>
#include <devtree/flat.h>
#include <devtree/devtree.h>
#include <devtree/driver.h>


struct fdt_node *
dt_node_get_fdt_node(
        struct dt_node *node)
{
    return node->backing_data;
}
int
dt_node_read_property_u32(
        struct dt_node *node,
        const char *prop_name,
        uint32_t *val_out)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);
 
    struct fdt_property *prop =
        fdt_find_property_by_name(fdt, fdt_node, prop_name);
    if(prop == NULL) {
        return -ENXIO;
    }

    size_t datalen = fdt_property_size(fdt, prop);
    fdt32_t *data = fdt_property_data(fdt, prop);

    if(datalen < 4) {
        return -EINVAL;
    }

    uint32_t value = fdttoh32(*data);
    if(val_out) {
        *val_out = value;
    }

    return 0;
}

size_t
dt_node_reg_count(
        struct dt_node *node)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);
    size_t count = fdt_node_reg_count(fdt, fdt_node);
    return count;
}

int
dt_node_read_reg(
        struct dt_node *node,
        size_t buflen,
        void __phys **addr_buf,
        size_t *size_buf)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);
    return fdt_node_read_reg(
            fdt,
            fdt_node,
            buflen,
            addr_buf,
            size_buf);
}

static int
dt_node_get_interrupt_parent_phandle(
        struct dt_node *node,
        fdt_phandle_t *phandle_out)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);

    while(node != NULL)
    {
        struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

        struct fdt_property *parent_prop;
        parent_prop = fdt_find_property_by_name(
                fdt,
                fdt_node,
                "interrupt-parent");
        if(parent_prop == NULL) {
            node = node->parent;
            continue;
        }

        size_t len = fdt_property_size(fdt, parent_prop);
        if(len != sizeof(fdt_phandle_t)) {
            return -EINVAL;
        }

        fdt_phandle_t phandle = *(fdt_phandle_t*)fdt_property_data(fdt, parent_prop);

        if(phandle_out) {
            *phandle_out = phandle;
        }
        return 0;
    }

    return -ENXIO;
}

static int
dt_node_get_interrupts_extended_irq_count(
        struct dt_node *node,
        size_t *count_out)
{
    return -EUNIMPL;
}

static int
dt_node_get_interrupts_irq_count(
        struct dt_node *node,
        size_t *count_out)
{
    int res;
    fdt_phandle_t parent_phandle;
    res = dt_node_get_interrupt_parent_phandle(
            node,
            &parent_phandle);
    if(res) {
        return res;
    }

    struct dt_node *interrupt_parent =
        devtree_get_node_by_phandle(node->dt, parent_phandle);
    if(interrupt_parent == NULL) {
        return -ENXIO;
    }

    uint32_t interrupt_cells;
    res = dt_node_read_property_u32(
            interrupt_parent,
            "#interrupt-cells",
            &interrupt_cells);
    if(res) {
        return res;
    }

    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *interrupt_prop;
    interrupt_prop = fdt_find_property_by_name(
            fdt,
            fdt_node,
            "interrupts");
    if(interrupt_prop == NULL) {
        return -ENXIO;
    }

    size_t prop_len = fdt_property_size(fdt, interrupt_prop);

    size_t count = prop_len / (interrupt_cells*4);
    
    if(count_out) {
        *count_out = count;
    }

    return 0;
}

size_t
dt_node_irq_count(
        struct dt_node *node)
{
    int res;
    size_t count;
    res = dt_node_get_interrupts_extended_irq_count(node, &count);
    if(res) {
        res = dt_node_get_interrupts_irq_count(node, &count);
        if(res) {
            count = 0;
        }
    }

    return count;
}

static int
dt_node_interrupts_extended_read_irq(
        struct dt_node *node,
        size_t index,
        irq_t *irq_out)
{
    return -EUNIMPL;
}

static int
dt_node_interrupts_read_irq(
        struct dt_node *node,
        size_t index,
        irq_t *irq_out)
{
    int res;
    fdt_phandle_t parent_phandle;
    res = dt_node_get_interrupt_parent_phandle(
            node,
            &parent_phandle);
    if(res) {
        return res;
    }

    struct dt_node *interrupt_parent =
        devtree_get_node_by_phandle(node->dt, parent_phandle);
    if(interrupt_parent == NULL) {
        return -ENXIO;
    }

    struct dt_driver *driver = interrupt_parent->driver;
    if(driver == NULL) {
        // The interrupt parent does not have a driver yet
        return -EDEFER;
    }

    uint32_t interrupt_cells;
    res = dt_node_read_property_u32(
            interrupt_parent,
            "#interrupt-cells",
            &interrupt_cells);
    if(res) {
        return res;
    }

    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *interrupt_prop;
    interrupt_prop = fdt_find_property_by_name(
            fdt,
            fdt_node,
            "interrupts");
    if(interrupt_prop == NULL) {
        return -ENXIO;
    }

    size_t prop_len = fdt_property_size(fdt, interrupt_prop);
    size_t offset = (index * 4 * interrupt_cells);
    if(offset + 4 > prop_len) {
        return -ENXIO;
    }

    fdt32_t *prop_data = fdt_property_data(fdt, interrupt_prop);
    fdt32_t *cells = prop_data + (index * interrupt_cells);

    irq_t irq =
        dt_driver_xlate_irq(
            driver,
            interrupt_parent,
            cells,
            interrupt_cells);

    if(irq_out) {
        *irq_out = irq;
    }

    return 0;

}

irq_t
dt_node_read_irq(
        struct dt_node *node,
        size_t index)
{
    int res;
    irq_t irq;
    res = dt_node_interrupts_extended_read_irq(node, index, &irq);
    if(res) {
        res = dt_node_interrupts_read_irq(node, index, &irq);
        if(res) {
            return NULL_IRQ;
        }
    }
    return irq;
}

