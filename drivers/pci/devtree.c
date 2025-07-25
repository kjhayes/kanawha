
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/mmio_ecam.h>
#include <devtree/driver.h>
#include <devtree/match.h>
#include <devtree/node.h>
#include <devtree/flat.h>
#include <devtree/devtree.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/mmio.h>

static int
pci_ecam_dt_probe(
        struct dt_driver *driver,
        struct dt_node *node)
{
    return 0;
}

static int
pci_ecam_dt_init_node(
        struct dt_driver *driver,
        struct dt_node *node)
{
    printk("pci_ecam_dt_init_node\n");
    int res;

    void __phys *phys_addr;
    size_t phys_size;

    res = dt_node_read_reg(
            node,
            1,
            &phys_addr,
            &phys_size);
    if(res) {
        return res;
    }

    void __phys *mmio_base = phys_addr;
    size_t mmio_size = phys_size;

    // Register the ECAM mechanism
    struct mmio_pci_ecam *ecam = kmalloc(sizeof(*ecam));
    if(ecam == NULL) {
        return -ENOMEM;
    }

    res = register_mmio_pci_ecam(
            ecam,
            0, // We will assume there is only a single segment
            mmio_base,
            mmio_size);
    if(res) {
        kfree(ecam);
        return res;
    }

    // NOTE: We leak the memory of "ecam", which means this driver can never be
    //       unloaded (that's fine because every pci driver will depend on this one
    //       so unloading it was never really an option to begin with)

    size_t bus_start = 0;
    size_t bus_end = 255;

    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);
    struct fdt_property *bus_range_prop = fdt_find_property_by_name(fdt, fdt_node, "bus-range");
    if(bus_range_prop != NULL) { 
        if(fdt_property_size(fdt, bus_range_prop) == 8) {
            fdt32_t *data = fdt_property_data(fdt, bus_range_prop);

            bus_start = fdttoh32(data[0]);
            bus_end = fdttoh32(data[1]);
        } else {
            wprintk("Found \"bus-range\" property on PCI device tree node, but it is the wrong size! (ignorning)\n");
        }
    }

    res = pci_probe_segment_with_assumed_buses(
            0,
            bus_start,
            bus_end - bus_start);
    if(res) {
        return res;
    }

    return 0;
}

static int
pci_ecam_dt_deinit_node(
        struct dt_driver *driver,
        struct dt_node *node)
{
    printk("pci_ecam_dt_deinit_node\n");
    return -EUNIMPL;
}

static irq_t
pci_ecam_dt_xlate_irq(
        struct dt_driver *driver,
        struct dt_node *node,
        const fdt32_t *cells,
        size_t cell_count)
{
    return NULL_IRQ;
}


struct dt_driver_ops
pci_ecam_dt_driver_ops = {
    .probe = pci_ecam_dt_probe,
    .init_node = pci_ecam_dt_init_node,
    .deinit_node = pci_ecam_dt_deinit_node,
    .xlate_irq = pci_ecam_dt_xlate_irq,
};

struct dt_node_id
pci_ecam_dt_ids[] = {
    {
        .compatible = "pci-host-ecam-generic"
    }
};

struct dt_driver
pci_ecam_dt_driver = {
    .num_ids = sizeof(pci_ecam_dt_ids)/sizeof(struct dt_node_id),
    .ids = pci_ecam_dt_ids,
    .ops = &pci_ecam_dt_driver_ops,
};

static int
register_devtree_pci_ecam_driver(void)
{
    int res;
    res = register_dt_driver(&pci_ecam_dt_driver);
    if(res) {
        return res;
    }
    return 0;
}
declare_init_desc(bus, register_devtree_pci_ecam_driver, "Registering Devtree PCI Driver");

