
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <devtree/driver.h>
#include <devtree/match.h>
#include <devtree/node.h>
#include <devtree/flat.h>
#include <devtree/devtree.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/mmio.h>

struct dt_pci_domain {
    void __mmio *mmio_region;
    size_t mmio_size;

    struct pci_domain pci_domain;
};

static inline size_t
pci_cam_offset(
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset)
{
    size_t val = 
        (((size_t)bus & 0xFF) << 16)
      | (((size_t)device & 0b11111) << 11)
      | (((size_t)func & 0b111) << 8)
      | ((size_t)offset & 0xFF);
    return val;
}

static inline size_t
pci_ecam_offset(
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset)
{
    size_t val = 
        (((size_t)bus & 0xFF) << 20)
      | (((size_t)device & 0b11111) << 15)
      | (((size_t)func & 0b111) << 12)
      | ((size_t)offset & 0xFF);
    return val;
}

static int
devtree_pci_ecam_readb(
        struct pci_domain *pci_domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t *out
        )
{
    struct dt_pci_domain *domain = container_of(pci_domain, struct dt_pci_domain, pci_domain);
    size_t mmio_offset = pci_ecam_offset(bus, device, func, offset);
    if((mmio_offset + 1) > domain->mmio_size) {
        return -ERANGE;
    }
    void __mmio *ptr = domain->mmio_region + mmio_offset;
    *out = mmio_readb(ptr);
    return 0;
}

static int
devtree_pci_ecam_readw(
        struct pci_domain *pci_domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t *out
        )
{
    struct dt_pci_domain *domain = container_of(pci_domain, struct dt_pci_domain, pci_domain);
    size_t mmio_offset = pci_ecam_offset(bus, device, func, offset);
    if((mmio_offset + 2) > domain->mmio_size) {
        return -ERANGE;
    }
    void __mmio *ptr = domain->mmio_region + mmio_offset;
    *out = mmio_readw(ptr);
    return 0;
}

static int
devtree_pci_ecam_readl(
        struct pci_domain *pci_domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t *out
        )
{
    struct dt_pci_domain *domain = container_of(pci_domain, struct dt_pci_domain, pci_domain);
    size_t mmio_offset = pci_ecam_offset(bus, device, func, offset);
    if((mmio_offset + 4) > domain->mmio_size) {
        return -ERANGE;
    }
    void __mmio *ptr = domain->mmio_region + mmio_offset;
    *out = mmio_readl(ptr);
    return 0;
}

static int
devtree_pci_ecam_writeb(
        struct pci_domain *pci_domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t in 
        )
{
    struct dt_pci_domain *domain = container_of(pci_domain, struct dt_pci_domain, pci_domain);
    size_t mmio_offset = pci_ecam_offset(bus, device, func, offset);
    if((mmio_offset + 1) > domain->mmio_size) {
        return -ERANGE;
    }
    void __mmio *ptr = domain->mmio_region + mmio_offset;
    mmio_writeb(ptr, in);
    return 0;
}

static int
devtree_pci_ecam_writew(
        struct pci_domain *pci_domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t in 
        )
{
    struct dt_pci_domain *domain = container_of(pci_domain, struct dt_pci_domain, pci_domain);
    size_t mmio_offset = pci_ecam_offset(bus, device, func, offset);
    if((mmio_offset + 2) > domain->mmio_size) {
        return -ERANGE;
    }
    void __mmio *ptr = domain->mmio_region + mmio_offset;
    mmio_writew(ptr, in);
    return 0;
}

static int
devtree_pci_ecam_writel(
        struct pci_domain *pci_domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t in 
        )
{
    struct dt_pci_domain *domain = container_of(pci_domain, struct dt_pci_domain, pci_domain);
    size_t mmio_offset = pci_ecam_offset(bus, device, func, offset);
    if((mmio_offset + 4) > domain->mmio_size) {
        return -ERANGE;
    }
    void __mmio *ptr = domain->mmio_region + mmio_offset;
    mmio_writel(ptr, in);
    return 0;
}


static struct pci_cam
devtree_pci_ecam = {
    .readb   = devtree_pci_ecam_readb,
    .readw  = devtree_pci_ecam_readw,
    .readl  = devtree_pci_ecam_readl,
    .writeb  = devtree_pci_ecam_writeb,
    .writew = devtree_pci_ecam_writew,
    .writel = devtree_pci_ecam_writel,
};

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

    struct dt_pci_domain *domain = kmalloc(sizeof(struct dt_pci_domain));
    if(domain == NULL) {
        return -ENOMEM;
    }
    memset(domain, 0, sizeof(struct dt_pci_domain));

    domain->mmio_size = phys_size;
    domain->mmio_region = mmio_map(phys_addr, phys_size);
    if(domain->mmio_region == NULL) {
        kfree(domain);
        return -ENOMEM;
    }

    size_t bus_start = 0;
    size_t bus_end = 255;

    // TODO look for the "bus-range" property to try and shrink the range if we know certain buses do not exist
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

    res = register_pci_domain_with_assumed_buses(
            &domain->pci_domain,
            &devtree_pci_ecam,
            bus_start,
            bus_end - bus_start);
    if(res) {
        mmio_unmap(domain->mmio_region, domain->mmio_size);
        kfree(domain);
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

