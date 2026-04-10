
#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/flat.h>
#include <devtree/match.h>
#include <devtree/node.h>
#include <kanawha/init.h>
#include <kanawha/mem_flags.h>
#include <kanawha/ramfile.h>

static void
linux_chosen_reserve_mem_flags_initrd(struct fdt *fdt, struct fdt_node *node)
{
    int res;

    struct fdt_property *start_prop =
        fdt_find_property_by_name(fdt, node, "linux,initrd-start");
    if(start_prop == NULL)
    {
        return;
    }
    struct fdt_property *end_prop =
        fdt_find_property_by_name(fdt, node, "linux,initrd-end");
    if(end_prop == NULL)
    {
        return;
    }

    size_t start_size = fdt_property_size(fdt, start_prop);
    size_t end_size = fdt_property_size(fdt, end_prop);
    void *start_data = fdt_property_data(fdt, start_prop);
    void *end_data = fdt_property_data(fdt, end_prop);

    uintptr_t start;
    switch(start_size)
    {
    case 1:
        start = *(uint8_t *)start_data;
        break;
    case 2:
        start = fdttoh16(*(fdt16_t *)start_data);
        break;
    case 4:
        start = fdttoh32(*(fdt32_t *)start_data);
        break;
    case 8:
        start = fdttoh64(*(fdt64_t *)start_data);
        break;
    default:
        return;
    }

    uintptr_t end;
    switch(end_size)
    {
    case 1:
        end = *(uint8_t *)end_data;
        break;
    case 2:
        end = fdttoh16(*(fdt16_t *)end_data);
        break;
    case 4:
        end = fdttoh32(*(fdt32_t *)end_data);
        break;
    case 8:
        end = fdttoh64(*(fdt64_t *)end_data);
        break;
    default:
        return;
    }

    DEBUG_ASSERT(start < end);

    size_t size = end - start;

    struct mem_flags *phys_map = get_phys_mem_flags();
    if(phys_map == NULL)
    {
        return;
    }

    res = mem_flags_clear_flags(phys_map, start, size, PHYS_MEM_FLAGS_AVAIL);
    if(res)
    {
        wprintk("Failed to reserve device tree /chosen initrd!\n");
    }
}

static void
linux_chosen_dt_probe_initrd(struct dt_node *node)
{
    int res;

    uintptr_t start, end;
    res = dt_node_read_property_unsigned(node, "linux,initrd-start", &start);
    if(res)
    {
        return;
    }
    res = dt_node_read_property_unsigned(node, "linux,initrd-end", &end);
    if(res)
    {
        return;
    }

    DEBUG_ASSERT(end > start);

    size_t size = end - start;

    printk("Found initrd in device tree [%p - %p) (size=%p)\n",
           start,
           end,
           size);

    res = mem_flags_check_region(get_phys_mem_flags(),
                                 start,
                                 size,
                                 0,
                                 PHYS_MEM_FLAGS_KERNEL | PHYS_MEM_FLAGS_AVAIL);
    if(res)
    {
        eprintk("Device tree initrd either was not properly reserved by the "
                "firmware or overlaps the kernel! (ignoring...)\n");
        return;
    }

    const char *ramfile_name = "initrd";
    printk("Creating ramfile \"%s\" from Device Tree initrd...\n",
           ramfile_name);
    res = create_ramfile(ramfile_name, (void __phys *)(uintptr_t)start, size);
    if(res)
    {
        eprintk("Failed to create ramfile from device tree!\n");
        return;
    }

    return;
}

static int
linux_chosen_dt_probe(struct dt_driver *driver, struct dt_node *node)
{
    return 0;
}
static int
linux_chosen_dt_init_node(struct dt_driver *driver, struct dt_node *node)
{
    printk("Found /chosen Node in Device Tree\n");
    linux_chosen_dt_probe_initrd(node);
    printk("Finished Processing Device Tree /chosen Node\n");
    return 0;
}
static int
linux_chosen_dt_deinit_node(struct dt_driver *driver, struct dt_node *node)
{
    return 0;
}

static struct dt_driver_ops linux_chosen_dt_driver_ops = {
    .probe = linux_chosen_dt_probe,
    .init_node = linux_chosen_dt_init_node,
    .deinit_node = linux_chosen_dt_deinit_node,
    .xlate_irq = dt_driver_cannot_xlate_irq,
};

static struct dt_node_id linux_chosen_dt_driver_ids[] = {
    {
        .name = "chosen",
    },
};

static struct dt_driver linux_chosen_dt_driver = {
    .ids = linux_chosen_dt_driver_ids,
    .num_ids = sizeof(linux_chosen_dt_driver_ids) / sizeof(struct dt_node_id),
    .ops = &linux_chosen_dt_driver_ops,
};

static int
register_linux_dt_chosen_driver(void)
{
    int res;
    res = register_dt_driver(&linux_chosen_dt_driver);
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init(late, register_linux_dt_chosen_driver);

static int
linux_dt_chosen_reserve_mem_flags(void)
{
    int res;
    struct mem_flags *phys_map = get_phys_mem_flags();

    struct devtree *dev_tree = devtree_get();
    if(dev_tree == NULL)
    {
        return -EDEFER;
    }

    struct fdt *fdt = devtree_get_fdt(dev_tree);

    DEBUG_ASSERT(fdt_check_header(fdt) == 0);

    struct fdt_node *node = fdt_find_node_by_unitname(fdt, "chosen");
    if(node == NULL)
    {
        // If the node doesn't exist that's fine.
        return 0;
    }

    linux_chosen_reserve_mem_flags_initrd(fdt, node);

    return 0;
}
declare_init_desc(mem_flags,
                  linux_dt_chosen_reserve_mem_flags,
                  "Reserving Memory for /chosen Node in Device Tree");
