
#include <devtree/devtree.h>
#include <devtree/driver.h>
#include <devtree/flat.h>
#include <devtree/match.h>
#include <devtree/node.h>
#include <drivers/pci/cfg.h>
#include <drivers/pci/mmio_ecam.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/intx.h>
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/mmio.h>
#include <kanawha/string.h>

static int
pci_ecam_irq_mapping_callback(
        struct dt_node *node,
        void *state,
        const fdt32_t *child_addr_cells,
        size_t child_addr_cell_count,
        const fdt32_t *child_irq_cells,
        size_t child_irq_cell_count,
        irq_t parent_irq)
{
    int res;

    struct pci_segment *segment = state;

    if(child_addr_cell_count != 3) {
        wprintk("pci_ecam_irq_mapping_callback: incorrect child address FDT cell width! (expected 3, got %d)\n",
                (int)child_addr_cell_count);
        return -EINVAL;
    }
    if(child_irq_cell_count != 1) {
        wprintk("pci_ecam_irq_mapping_callback: incorrect child irq FDT cell width! (expected 1, got %d)\n",
                (int)child_irq_cell_count);
        return -EINVAL;
    }

    uint32_t irq_cell = fdttoh32(child_irq_cells[0]);
    pci_intx_pin_t pin = PCI_INTX_NONE;
    switch(irq_cell) {
        case 1: pin = PCI_INTX_INTA; break;
        case 2: pin = PCI_INTX_INTB; break;
        case 3: pin = PCI_INTX_INTC; break;
        case 4: pin = PCI_INTX_INTD; break;
        default:
            wprintk("pci_ecam_irq_mapping_callback: invalid PCI pin specifier in device tree! (val=%d)\n",
                    (int)irq_cell);
            return -EINVAL;
    }

    uint32_t bdf_cell = fdttoh32(child_addr_cells[0]);

    struct pci_func *func = NULL;

    uint16_t segment_id = segment->segment_id;
    uint8_t bus_id    = (bdf_cell >> 16) & ((1UL<<8)-1);
    uint8_t device_id = (bdf_cell >> 11) & ((1UL<<5)-1);
    uint8_t func_id   = (bdf_cell >> 8)  & ((1UL<<3)-1);

    func = pci_lookup_func(
            segment_id,
            bus_id,
            device_id,
            func_id);

    if(func == NULL) {
        wprintk("pci_ecam_irq_mapping_callback: failed to find PCI device %u.%u.%u.%u!\n",
            (unsigned)segment_id,
            (unsigned)bus_id,
            (unsigned)device_id,
            (unsigned)func_id);
        return -ENXIO;
    }

    res = pci_func_route_intx(
            func,
            pin,
            parent_irq);
    if(res) {
        wprintk("pci_ecam_irq_mapping_callback: failed to route %u.%u.%u.%u (%s) to IRQ %d! (err=%s)\n",
            (unsigned)segment_id,
            (unsigned)bus_id,
            (unsigned)device_id,
            (unsigned)func_id,
            pci_intx_pin_to_string(pin),
            (int)parent_irq,
            errnostr(res));
        return res;
    }

    printk("Routed IRQ %d to PCI %u.%u.%u.%u (%s)\n",
            (int)parent_irq,
            (unsigned)segment_id,
            (unsigned)bus_id,
            (unsigned)device_id,
            (unsigned)func_id,
            pci_intx_pin_to_string(pin));

    return 0;
}

static int
pci_ecam_dt_probe(struct dt_driver *driver, struct dt_node *node)
{
    return 0;
}

static int
pci_ecam_dt_init_node(struct dt_driver *driver, struct dt_node *node)
{
    printk("pci_ecam_dt_init_node\n");
    int res;

    void __phys *phys_addr;
    size_t phys_size;

    res = dt_node_read_reg(node, 1, &phys_addr, &phys_size);
    if(res)
    {
        return res;
    }

    void __phys *mmio_base = phys_addr;
    size_t mmio_size = phys_size;

    // Register the ECAM mechanism
    struct mmio_pci_ecam *ecam = kmalloc(sizeof(*ecam), KM_KERNEL);
    if(ecam == NULL)
    {
        return -ENOMEM;
    }

    res = register_mmio_pci_ecam(
        ecam,
        0, // We will assume there is only a single segment
        mmio_base,
        mmio_size);
    if(res)
    {
        kfree(ecam);
        return res;
    }

    // NOTE: We leak the memory of "ecam", which means this driver can never be
    //       unloaded (that's fine because every pci driver will depend on this
    //       one so unloading it was never really an option to begin with)

    size_t bus_start = 0;
    size_t bus_end = 255;

    struct fdt *fdt = devtree_get_fdt(node->dt);
    struct fdt_node *fdt_node = dt_node_get_fdt_node(node);
    struct fdt_property *bus_range_prop =
        fdt_find_property_by_name(fdt, fdt_node, "bus-range");
    if(bus_range_prop != NULL)
    {
        if(fdt_property_size(fdt, bus_range_prop) == 8)
        {
            fdt32_t *data = fdt_property_data(fdt, bus_range_prop);

            bus_start = fdttoh32(data[0]);
            bus_end = fdttoh32(data[1]);
        }
        else
        {
            wprintk("Found \"bus-range\" property on PCI device tree "
                    "node, but "
                    "it is the wrong size! (ignorning)\n");
        }
    }

    struct pci_segment *segment = pci_segment_create_or_get(0);
    if(segment == NULL)
    {
        wprintk("Failed to obtain PCI segment 0!\n");
        return -ENXIO;
    }

    {
        size_t addr_cells = fdt_node_address_cells(fdt, fdt_node);
        size_t size_cells = fdt_node_size_cells(fdt, fdt_node);
        size_t pci_addr_cells = 3;
        size_t entry_cells = (addr_cells + size_cells + pci_addr_cells);

        struct fdt_property *ranges_prop =
            fdt_find_property_by_name(fdt, fdt_node, "ranges");
        if(ranges_prop != NULL)
        {
            printk("Found ranges prop of length %lu\n",
                   (ul_t)fdttoh32(ranges_prop->len));
            fdt32_t *cells = fdt_property_data(fdt, ranges_prop);
            size_t num_cells =
                fdt_property_size(fdt, ranges_prop) / sizeof(fdt32_t);

            size_t num_entries = num_cells / entry_cells;
            DEBUG_ASSERT((num_cells % entry_cells) == 0);
            for(size_t i = 0; i < num_entries; i++)
            {
                fdt32_t *pci_addr_data = &cells[(i * entry_cells)];
                fdt32_t *cpu_addr_data =
                    &cells[(i * entry_cells) + pci_addr_cells];
                fdt32_t *size_data =
                    &cells[(i * entry_cells) + pci_addr_cells + addr_cells];

                size_t size;
                if(size_cells == 1)
                {
                    size = fdttoh32(size_data[0]);
                }
                else if(size_cells == 2)
                {
                    size = fdttoh64(*(fdt64_t *)size_data);
                }
                else
                {
                    continue;
                }

                uint64_t cpu_addr;
                if(addr_cells == 1)
                {
                    cpu_addr = fdttoh32(cpu_addr_data[0]);
                }
                else if(addr_cells == 2)
                {
                    cpu_addr = fdttoh64(*(fdt64_t *)cpu_addr_data);
                }
                else
                {
                    continue;
                }

                uint32_t pci_flags = fdttoh32(pci_addr_data[0]);
                uint64_t pci_addr = fdttoh64(*(fdt64_t *)&pci_addr_data[1]);

                int space = (pci_flags >> 24) & 0x3;

                if((space & 2) && pci_addr != cpu_addr)
                {
                    wprintk("Device Tree PCI \"ranges\" mismatch between CPU "
                            "physical and PCI bus addresses!"
                            " (cpu=%p, pci=%p)\n",
                            (uintptr_t)cpu_addr,
                            (uintptr_t)pci_addr);
                    continue;
                }
                if(space == 0)
                {
                    // This represents configuration space
                    pci_segment_set_mmio_flags(segment,
                                               cpu_addr,
                                               size,
                                               PCI_MMIO_MEM_CONFIG);
                }
                else if(space & 2)
                {
                    // This is an MMIO range
                    pci_segment_set_mmio_flags(segment,
                                               cpu_addr,
                                               size,
                                               (PCI_MMIO_MEM_SNOOPED) |
                                                   (((pci_flags >> 30) & 1)
                                                        ? PCI_MMIO_MEM_PREFETCH
                                                        : 0));
                }
                else
                {
                    // This is a PIO range
                    pci_segment_set_pio_flags(segment,
                                              cpu_addr,
                                              size,
                                              PCI_PIO_MEM_SNOOPED);
                }

                printk("Device Tree PCI Range: pci=%p, cpu=%p, size=%p, "
                       "flags=0x%lx\n",
                       (uintptr_t)pci_addr,
                       (uintptr_t)cpu_addr,
                       (uintptr_t)size,
                       (ul_t)pci_flags);
            }
        }
    }

    res = pci_segment_probe(segment, bus_start, bus_end - bus_start);
    if(res)
    {
        return res;
    }

    res = dt_node_for_each_irq_mapping(
            node,
            segment,
            pci_ecam_irq_mapping_callback);
    if(res) {
        wprintk("PCI ECAM: failed to walk device tree IRQ mappings!\n");
    }

    return 0;
}

static int
pci_ecam_dt_deinit_node(struct dt_driver *driver, struct dt_node *node)
{
    printk("pci_ecam_dt_deinit_node\n");
    return -EUNIMPL;
}

static irq_t
pci_ecam_dt_xlate_irq(struct dt_driver *driver,
                      struct dt_node *node,
                      const fdt32_t *cells,
                      size_t cell_count)
{
    return NULL_IRQ;
}

static irq_t
pci_ecam_dt_xlate_irq_map(struct dt_driver *driver,
                      struct dt_node *node,
                      const fdt32_t *addr_cells,
                      size_t addr_cell_count,
                      const fdt32_t *irq_cells,
                      size_t irq_cell_count)
{
    return NULL_IRQ;
}

struct dt_driver_ops pci_ecam_dt_driver_ops = {
    .probe = pci_ecam_dt_probe,
    .init_node = pci_ecam_dt_init_node,
    .deinit_node = pci_ecam_dt_deinit_node,
    .xlate_irq = pci_ecam_dt_xlate_irq,
    .xlate_irq_map = pci_ecam_dt_xlate_irq_map,
};

struct dt_node_id pci_ecam_dt_ids[] = {{.compatible = "pci-host-ecam-generic"}};

struct dt_driver pci_ecam_dt_driver = {
    .num_ids = sizeof(pci_ecam_dt_ids) / sizeof(struct dt_node_id),
    .ids = pci_ecam_dt_ids,
    .ops = &pci_ecam_dt_driver_ops,
};

static int
register_devtree_pci_ecam_driver(void)
{
    int res;
    res = register_dt_driver(&pci_ecam_dt_driver);
    if(res)
    {
        return res;
    }
    return 0;
}
declare_init_desc(bus,
                  register_devtree_pci_ecam_driver,
                  "Registering Devtree PCI Driver");
