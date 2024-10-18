
#include <kanawha/stdint.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>

static int
pci_probe_bridge(
        struct pci_func *func)
{
    int res;

    uint8_t hdr_type;
    pci_func_readb(func, PCI_CFG_HEADER_TYPE, &hdr_type);

    if((hdr_type & 0x7F) == PCI_HEADER_TYPE_PCI_PCI_BRIDGE) {
        // Cross the PCI bridge
        uint8_t sec_bus;
        printk("Found PCI-to-PCI Bridge\n");
        pci_func_readb(func, PCI_CFG_PCI_BRIDGE_SECONDARY_BUS, &sec_bus);
        res = pci_probe_bus(func->device->bus->domain, sec_bus);
        if(res) {
            eprintk("Failed to enumerate secondary PCI bus %u of domain %lu\n",
                    sec_bus, func->domain->domain_id);
        }
    }

    return 0;
}

static int
pci_setup_bars(
        struct pci_func *func)
{
    for(int i = 0; i < 6; i++)
    {
        struct pci_bar *bar = &func->bars[i];

        uint64_t original = (uint32_t)pci_func_raw_read_bar(func, i);
        if(original & 1) {
            bar->type = PCI_BAR_PIO;
        } else {
            bar->type = PCI_BAR_MMIO;
            bar->mmio.type = (original & 0x6) >> 1;
            bar->mmio.prefetch = (original & 0x8) >> 3;
            if(bar->mmio.type == 2) {
                original |= (((uint64_t)pci_func_raw_read_bar(func, i+1)) << 32);
                i++; // Skip a BAR
                if(i >= 6) {
                    bar->type = PCI_BAR_NONE;
                    eprintk("PCI BAR 5 was marked as a 64-bit BAR!\n");
                    break;
                }
                func->bars[i].type = PCI_BAR_NONE; // Mark the upper half as "none"
            }
        }

        dprintk("original=0x%llx\n", (ull_t)original);
        pci_func_raw_write_bar(func, i, 0xFFFFFFFFULL); 
        uint64_t masked = pci_func_raw_read_bar(func, i);
        if(bar->type == PCI_BAR_MMIO && bar->mmio.type == 2) {
            pci_func_raw_write_bar(func, i+1, 0xFFFFFFFFULL);
            masked |= (((uint64_t)pci_func_raw_read_bar(func, i+1)) << 32);
        }

        dprintk("masked=0x%llx\n", (ull_t)masked);
        masked &= ~(bar->type == PCI_BAR_PIO ? 0x3ULL : 0xFULL);
        dprintk("masked=0x%llx\n", (ull_t)masked);
        uint64_t size_mask = 0xFFFFFFFF;
        if(bar->type == PCI_BAR_MMIO) {
            if(bar->mmio.type == 2) {
                size_mask = 0xFFFFFFFFFFFFFFFF;
            } else if(bar->mmio.type == 1) {
                size_mask = 0xFFFF;
            }
        }
        size_t size = (((~masked) & size_mask)+1) & size_mask;

        pci_func_raw_write_bar(func, i, (uint32_t)original);
        if(bar->type == PCI_BAR_MMIO && bar->mmio.type == 2) {
            pci_func_raw_write_bar(func, i+1, (uint32_t)(original>>32));
        }

        if(size == 0) {
            memset(bar, 0, sizeof(struct pci_bar));
            bar->type = PCI_BAR_NONE;
            continue;
        } 

        bar->size = size;

        if(bar->type == PCI_BAR_PIO) {
#ifndef CONFIG_PORT_IO
            eprintk("Found PCI Port I/O Bar with CONFIG_PORT_IO disabled!\n");
            continue;
#else
            bar->phys_addr = original & ~0x3;
            bar->pio.base = bar->phys_addr;
#endif
        } else {
            // MMIO
            bar->phys_addr = original & ~0xF;

            bar->mmio.base = mmio_map(bar->phys_addr, size);
            if(bar->mmio.base == NULL) {
                eprintk("Failed to map PCI MMIO BAR (phys_addr=%p)\n",
                        bar->phys_addr);
                bar->type = PCI_BAR_NONE;
                continue;
            }
        }
    }
    return 0;
}

int
pci_probe_func(
        struct pci_device *device,
        uint8_t index)
{
    int res;

    struct pci_bus *bus = device->bus;
    uint16_t vendor_id;
    pci_bus_readw(bus, device->index, index, PCI_CFG_VENDOR_ID, &vendor_id);

    if(vendor_id == 0xFFFF) {
        return -ENXIO;
    }

    struct pci_func *func = kmalloc(sizeof(struct pci_func));
    if(func == NULL) {
        eprintk("Failed to allocate PCI device struct!\n");
        return -ENOMEM;
    }

    func->domain = bus->domain;
    func->index = index;

    ilist_push_tail(&device->function_list, &func->device_node);
    func->device = device;

    pci_bus_readw(bus, device->index, index, PCI_CFG_VENDOR_ID, &func->vendor_id);
    pci_bus_readw(bus, device->index, index, PCI_CFG_DEVICE_ID, &func->device_id);

    printk("PCI Function: %d.%d -> ID(%x:%x)\n",
            device->index, index, func->vendor_id, func->device_id);

    pci_probe_bridge(func);

    pci_setup_bars(func);

    res = register_pci_func(func);
    if(res) {
        ilist_remove(&device->function_list, &func->device_node);
        kfree(func);
        return res;
    }

    return 0;
}

