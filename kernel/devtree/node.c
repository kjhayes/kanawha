
#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/flat.h>
#include <devtree/node.h>

#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

struct fdt_node *
dt_node_get_fdt_node(struct dt_node *node)
{
    return node->backing_data;
}

const char *
dt_node_get_name(struct dt_node *node)
{
    const char *name;
    int irq_flags = spin_lock_irq_save(&node->name_lock);
    if(node->name == NULL)
    {
        struct fdt *fdt = devtree_get_fdt(node->dt);
        struct fdt_node *fdt_node = dt_node_get_fdt_node(node);
        char *unitname = fdt_node_unitname(fdt, fdt_node);
        size_t len = 0;
        while(unitname[len] && unitname[len] != '@')
        {
            len++;
        }

        char *name_buf = kmalloc(len + 1, KM_KERNEL);
        if(name_buf == NULL)
        {
            spin_unlock_irq_restore(&node->name_lock, irq_flags);
            return NULL;
        }

        strncpy(name_buf, unitname, len + 1);
        name_buf[len] = '\0';

        node->name = name_buf;
    }
    name = node->name;
    spin_unlock_irq_restore(&node->name_lock, irq_flags);
    return name;
}

int
dt_node_read_property_u32(struct dt_node *node,
                          const char *prop_name,
                          uint32_t *val_out)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *prop =
        fdt_find_property_by_name(fdt, fdt_node, prop_name);
    if(prop == NULL)
    {
        return -ENXIO;
    }

    size_t datalen = fdt_property_size(fdt, prop);
    fdt32_t *data = fdt_property_data(fdt, prop);

    if(datalen != 4)
    {
        return -EINVAL;
    }

    uint32_t value = fdttoh32(*data);
    if(val_out)
    {
        *val_out = value;
    }

    return 0;
}

int
dt_node_read_property_u64(struct dt_node *node,
                          const char *prop_name,
                          uint64_t *val_out)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *prop =
        fdt_find_property_by_name(fdt, fdt_node, prop_name);
    if(prop == NULL)
    {
        return -ENXIO;
    }

    size_t datalen = fdt_property_size(fdt, prop);
    fdt64_t *data = fdt_property_data(fdt, prop);

    if(datalen != 8)
    {
        return -EINVAL;
    }

    uint64_t value = fdttoh64(*data);
    if(val_out)
    {
        *val_out = value;
    }

    return 0;
}

int
dt_node_read_property_unsigned(struct dt_node *node,
                               const char *prop_name,
                               uintptr_t *val_out)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *prop =
        fdt_find_property_by_name(fdt, fdt_node, prop_name);
    if(prop == NULL)
    {
        return -ENXIO;
    }

    size_t datalen = fdt_property_size(fdt, prop);
    void *data = fdt_property_data(fdt, prop);

    uintptr_t value;

    switch(datalen)
    {
    case 1:
        value = *(uint8_t *)data;
        break;
    case 2:
        value = fdttoh16(*(fdt16_t *)data);
        break;
    case 4:
        value = fdttoh32(*(fdt32_t *)data);
        break;
    case 8:
        value = fdttoh64(*(fdt64_t *)data);
        break;
    default:
        return -EINVAL;
    }

    if(val_out)
    {
        *val_out = value;
    }

    return 0;
}

int
dt_node_check_device_type(struct dt_node *node, const char *device_type)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *prop =
        fdt_find_property_by_name(fdt, fdt_node, "device_type");
    if(prop == NULL)
    {
        return 1;
    }

    char *data = fdt_property_data(fdt, prop);
    size_t prop_len = fdt_property_size(fdt, prop);
    size_t device_type_len = strlen(device_type);
    if((device_type_len + 1) != prop_len)
    {
        return 1;
    }

    return strcmp(device_type, data);
}

size_t
dt_node_reg_count(struct dt_node *node)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);
    size_t count = fdt_node_reg_count(fdt, fdt_node);
    return count;
}

int
dt_node_read_reg(struct dt_node *node,
                 size_t buflen,
                 void __phys **addr_buf,
                 size_t *size_buf)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);
    return fdt_node_read_reg(fdt, fdt_node, buflen, addr_buf, size_buf);
}

static int
dt_node_get_interrupt_parent_phandle(struct dt_node *node,
                                     fdt_phandle_t *phandle_out)
{
    struct fdt *fdt = devtree_get_fdt(node->dt);

    while(node != NULL)
    {
        struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

        struct fdt_property *parent_prop;
        parent_prop =
            fdt_find_property_by_name(fdt, fdt_node, "interrupt-parent");
        if(parent_prop == NULL)
        {
            node = node->parent;
            continue;
        }

        size_t len = fdt_property_size(fdt, parent_prop);
        if(len != sizeof(fdt_phandle_t))
        {
            return -EINVAL;
        }

        fdt_phandle_t phandle =
            *(fdt_phandle_t *)fdt_property_data(fdt, parent_prop);

        if(phandle_out)
        {
            *phandle_out = phandle;
        }
        return 0;
    }

    return -ENXIO;
}

static int
dt_node_get_interrupts_extended_irq_count(struct dt_node *node,
                                          size_t *count_out)
{
    int res;

    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *prop =
        fdt_find_property_by_name(fdt, fdt_node, "interrupts-extended");
    if(prop == NULL)
    {
        return -ENXIO;
    }

    size_t prop_len = fdt_property_size(fdt, prop);
    size_t cell_len = prop_len / sizeof(fdt32_t);

    fdt32_t *cell_ptr = fdt_property_data(fdt, prop);

    size_t irq_count = 0;

    for(size_t i = 0; i < cell_len; i++)
    {
        fdt_phandle_t phandle = cell_ptr[i];

        struct dt_node *irq_parent =
            devtree_get_node_by_phandle(node->dt, phandle);
        if(irq_parent == NULL)
        {
            eprintk("Failed to get \"interrupts-extended\" property "
                    "interrupt "
                    "parent node!\n");
            return -EINVAL;
        }

        uint32_t interrupt_cells;
        res = dt_node_read_property_u32(irq_parent,
                                        "#interrupt-cells",
                                        &interrupt_cells);
        if(res)
        {
            eprintk("Failed to get \"interrupts-extended\" interrupt "
                    "parent "
                    "node \"#interrupt-cells\" property!\n");
            return res;
        }

        if(cell_len - (i + 1) >= interrupt_cells)
        {
            irq_count++;
            i += interrupt_cells;
        }
        else
        {
            eprintk("Failed to get \"interrupts-extended\" not "
                    "enough room for "
                    "interrupt parent node IRQ descriptor! "
                    "(interrupt_cells = "
                    "0x%lx)\n",
                    (ul_t)interrupt_cells);
            return -EINVAL;
        }
    }

    if(count_out)
    {
        *count_out = irq_count;
    }

    return 0;
}

static int
dt_node_get_interrupts_irq_count(struct dt_node *node, size_t *count_out)
{
    int res;
    fdt_phandle_t parent_phandle;
    res = dt_node_get_interrupt_parent_phandle(node, &parent_phandle);
    if(res)
    {
        return res;
    }

    struct dt_node *interrupt_parent =
        devtree_get_node_by_phandle(node->dt, parent_phandle);
    if(interrupt_parent == NULL)
    {
        return -ENXIO;
    }

    uint32_t interrupt_cells;
    res = dt_node_read_property_u32(interrupt_parent,
                                    "#interrupt-cells",
                                    &interrupt_cells);
    if(res)
    {
        return res;
    }

    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *interrupt_prop;
    interrupt_prop = fdt_find_property_by_name(fdt, fdt_node, "interrupts");
    if(interrupt_prop == NULL)
    {
        return -ENXIO;
    }

    size_t prop_len = fdt_property_size(fdt, interrupt_prop);

    size_t count = prop_len / (interrupt_cells * 4);

    if(count_out)
    {
        *count_out = count;
    }

    return 0;
}

int
dt_node_irq_count(struct dt_node *node, size_t *size_out)
{
    int res;
    res = dt_node_get_interrupts_extended_irq_count(node, size_out);
    if(res)
    {
        res = dt_node_get_interrupts_irq_count(node, size_out);
        if(res)
        {
            return res;
        }
    }
    return 0;
}

static int
dt_node_interrupts_extended_read_irq(struct dt_node *node,
                                     size_t index,
                                     irq_t *irq_out)
{
    int res;

    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *prop =
        fdt_find_property_by_name(fdt, fdt_node, "interrupts-extended");
    if(prop == NULL)
    {
        return -ENXIO;
    }

    size_t prop_len = fdt_property_size(fdt, prop);
    size_t cell_len = prop_len / sizeof(fdt32_t);

    fdt32_t *cell_ptr = fdt_property_data(fdt, prop);

    size_t cur_irq_index = 0;

    for(size_t i = 0; i < cell_len; i++)
    {
        fdt_phandle_t phandle = cell_ptr[i];

        struct dt_node *irq_parent =
            devtree_get_node_by_phandle(node->dt, phandle);
        if(irq_parent == NULL)
        {
            eprintk("Failed to get \"interrupts-extended\" property "
                    "interrupt "
                    "parent node!\n");
            return -EINVAL;
        }
        if(irq_parent->driver == NULL)
        {
            wprintk("Un-driven interrupt parent in device tree (node=%s, "
                    "irq_parent=%s) Deferring...\n",
                    fdt_node_unitname(fdt, dt_node_get_fdt_node(node)),
                    fdt_node_unitname(fdt, dt_node_get_fdt_node(irq_parent)));
            return -EDEFER;
        }

        uint32_t interrupt_cells;
        res = dt_node_read_property_u32(irq_parent,
                                        "#interrupt-cells",
                                        &interrupt_cells);
        if(res)
        {
            eprintk("Failed to get \"interrupts-extended\" interrupt "
                    "parent "
                    "node \"#interrupt-cells\" property!\n");
            return res;
        }

        if(cell_len - (i + 1) >= interrupt_cells)
        {
            if(cur_irq_index == index)
            {
                irq_t irq = dt_driver_xlate_irq(irq_parent->driver,
                                                irq_parent,
                                                &cell_ptr[i + 1],
                                                interrupt_cells);
                if(irq_out)
                {
                    *irq_out = irq;
                }
                return 0;
            }
            cur_irq_index++;
            i += interrupt_cells;
        }
        else
        {
            return -EINVAL;
        }
    }

    return -ENXIO;
}

static int
dt_node_interrupts_read_irq(struct dt_node *node, size_t index, irq_t *irq_out)
{
    int res;
    fdt_phandle_t parent_phandle;
    res = dt_node_get_interrupt_parent_phandle(node, &parent_phandle);
    if(res)
    {
        return res;
    }

    struct dt_node *interrupt_parent =
        devtree_get_node_by_phandle(node->dt, parent_phandle);
    if(interrupt_parent == NULL)
    {
        return -ENXIO;
    }

    struct dt_driver *driver = interrupt_parent->driver;
    if(driver == NULL)
    {
        // The interrupt parent does not have a driver yet
        return -EDEFER;
    }

    uint32_t interrupt_cells;
    res = dt_node_read_property_u32(interrupt_parent,
                                    "#interrupt-cells",
                                    &interrupt_cells);
    if(res)
    {
        return res;
    }

    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);

    struct fdt_property *interrupt_prop;
    interrupt_prop = fdt_find_property_by_name(fdt, fdt_node, "interrupts");
    if(interrupt_prop == NULL)
    {
        return -ENXIO;
    }

    size_t prop_len = fdt_property_size(fdt, interrupt_prop);
    size_t offset = (index * 4 * interrupt_cells);
    if(offset + 4 > prop_len)
    {
        return -ENXIO;
    }

    fdt32_t *prop_data = fdt_property_data(fdt, interrupt_prop);
    fdt32_t *cells = prop_data + (index * interrupt_cells);

    irq_t irq =
        dt_driver_xlate_irq(driver, interrupt_parent, cells, interrupt_cells);

    if(irq_out)
    {
        *irq_out = irq;
    }

    return 0;
}

int
dt_node_read_irq(struct dt_node *node, size_t index, irq_t *irq_out)
{
    int res;
    irq_t irq;
    res = dt_node_interrupts_extended_read_irq(node, index, irq_out);
    if(res)
    {
        if(res == -EDEFER)
        {
            return res;
        }
        res = dt_node_interrupts_read_irq(node, index, irq_out);
        if(res)
        {
            return res;
        }
    }
    return 0;
}
