
#include <kanawha/types.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/page_alloc.h>
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/cap.h>
#include <drivers/pci/irq.h>

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
        res = pci_probe_bus(func->device->bus->segment, sec_bus);
        if(res) {
            eprintk("Failed to enumerate secondary PCI bus %u of segment %lu\n",
                    sec_bus, func->segment->segment_id);
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
        int bar_index = i;
        int upper_bar_index = i+1;

        uint64_t original = (uint32_t)pci_func_raw_read_bar(func, bar_index);
        if(original & 1) {
#ifdef CONFIG_PORT_IO
            bar->type = PCI_BAR_PIO;
#else
            eprintk("Found Port PCI Bar without CONFIG_PORT_IO set!\n");
            return -EINVAL;
#endif
        } else {
            bar->type = PCI_BAR_MMIO;
            bar->mmio.type = (original & 0x6ULL) >> 1;
            bar->mmio.prefetch = (original & 0x8ULL) >> 3;

            if(bar->mmio.type == 2) {

                original |= (((uint64_t)pci_func_raw_read_bar(func, upper_bar_index)) << 32);

                i++; // Skip a BAR

                if(upper_bar_index >= 6) {
                    bar->type = PCI_BAR_NONE;
                    eprintk("PCI BAR 5 was marked as a 64-bit BAR!\n");
                    break;
                }
                func->bars[i].type = PCI_BAR_NONE; // Mark the upper half as "none"
            }
        }

        dprintk("original=0x%llx\n", (ull_t)original);
        pci_func_raw_write_bar(func, bar_index, 0xFFFFFFFFULL); 
        uint64_t masked = pci_func_raw_read_bar(func, bar_index);
        if(bar->type == PCI_BAR_MMIO && bar->mmio.type == 2) {
            pci_func_raw_write_bar(func, upper_bar_index, 0xFFFFFFFFULL);
            uint64_t upper_masked = (uint64_t)pci_func_raw_read_bar(func, upper_bar_index);
            masked |= (upper_masked << 32);
        }

        dprintk("masked=0x%llx\n", (ull_t)masked);
#ifdef CONFIG_PORT_IO
        masked &= ~(bar->type == PCI_BAR_PIO ? 0x3ULL : 0xFULL);
#else
        masked &= ~0xFULL;
#endif
        dprintk("masked=0x%llx\n", (ull_t)masked);
        uint64_t size_mask = 0xFFFFFFFFULL;
        if(bar->type == PCI_BAR_MMIO) {
            if(bar->mmio.type == 2) {
                size_mask = 0xFFFFFFFFFFFFFFFFULL;
            } else if(bar->mmio.type == 1) {
                size_mask = 0xFFFFULL;
            }
        }

        size_t size = (((~masked) & size_mask)+1) & size_mask;
        dprintk("masked = %p, size_mask = %p, size = %p\n",
                (void*)masked,
                (void*)size_mask,
                (void*)size);

        pci_func_raw_write_bar(func, bar_index, (uint32_t)original);
        if(bar->type == PCI_BAR_MMIO && bar->mmio.type == 2) {
            pci_func_raw_write_bar(func, upper_bar_index, (uint32_t)(original>>32));
        }

        if(size == 0) {
            memset(bar, 0, sizeof(struct pci_bar));
            bar->type = PCI_BAR_NONE;
            continue;
        } 

        bar->size = size;

#ifdef CONFIG_PORT_IO
        if(bar->type == PCI_BAR_PIO) {
            bar->phys_addr = (void __phys *)(uintptr_t)(original & ~0x3ULL);
            bar->pio.base = (uintptr_t)(bar->phys_addr);
        } else {
#endif
            // MMIO
            bar->phys_addr = (void __phys *)(uintptr_t)(original & ~0xFULL);

#ifdef CONFIG_PCI_ALLOC_UNINITIALIZED_MMIO_BARS
            if(bar->phys_addr == 0) {
                int res;
                order_t order = ptr_orderof(bar->size);
                if(order < 12) {
                    order = 12;
                }
                unsigned long flags = 0;
                if(bar->mmio.type == 2) {
                    // 64-bit bar
                } else {
                    flags |= PAGE_ALLOC_32BIT;
                }
                res = page_alloc(order, &bar->phys_addr, flags);
                if(res) {
                    wprintk("Failed to remap uninitialized PCI MMIO BAR! (err=%s)\n",
                            errnostr(res));
                    bar->phys_addr = 0;
                } else {
                    pci_func_raw_write_bar(func, bar_index, ((uint32_t)(uintptr_t)bar->phys_addr) | (original & 0xFULL));
                    if(bar->mmio.type == 2) {
                        pci_func_raw_write_bar(func, upper_bar_index, (uint32_t)((uintptr_t)bar->phys_addr>>32));
                    }
                    printk("Remapped Uninitialized PCI MMIO BAR to physical addr=%p\n", bar->phys_addr);
                }
            }
#endif

            bar->mmio.base = mmio_map((void __phys *)bar->phys_addr, size);
            if(bar->mmio.base == NULL) {
                eprintk("Failed to map PCI MMIO BAR (phys_addr=%p) (err=%s)\n",
                        bar->phys_addr);
                bar->type = PCI_BAR_NONE;
                continue;
            }
#ifdef CONFIG_PORT_IO
        }
#endif
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

    struct pci_func *func = kmalloc(sizeof(struct pci_func), KM_KERNEL);
    if(func == NULL) {
        eprintk("Failed to allocate PCI device struct!\n");
        return -ENOMEM;
    }

    func->segment = bus->segment;
    func->index = index;

    ilist_push_tail(&device->function_list, &func->device_node);
    func->device = device;

    pci_bus_readw(bus, device->index, index, PCI_CFG_VENDOR_ID, &func->vendor_id);
    pci_bus_readw(bus, device->index, index, PCI_CFG_DEVICE_ID, &func->device_id);
    pci_bus_readb(bus, device->index, index, PCI_CFG_CLASS,     &func->class_id);
    pci_bus_readb(bus, device->index, index, PCI_CFG_SUBCLASS,  &func->subclass_id);
    pci_bus_readb(bus, device->index, index, PCI_CFG_PROG_IF,   &func->prog_if_id);

    printk("PCI Function: %d.%d -> ID(%x:%x)\n",
            device->index, index, func->vendor_id, func->device_id);

    pci_probe_bridge(func);

    uint8_t hdr_type;
    pci_func_readb(func, PCI_CFG_HEADER_TYPE, &hdr_type);

    ilist_init(&func->cap_list);

    if((hdr_type & 0x7F) == PCI_HEADER_TYPE_DEVICE) {
        res = pci_setup_bars(func);
        if(res) {
            eprintk("Failed to initialize PCI device BAR(s)! (err=%s)\n",
                    errnostr(res));
            ilist_remove(&device->function_list, &func->device_node);
            kfree(func);
            return res;
        }

        res = pci_func_init_caps(func);
        if(res) {
            eprintk("Failed to initialize PCI device capabilities! (err=%s)\n",
                    errnostr(res));
            // TODO deinit bars
            ilist_remove(&device->function_list, &func->device_node);
            kfree(func);
            return res;
        }

    } else {
        for(int i = 0; i < 6; i++) {
            func->bars[i].type = PCI_BAR_NONE;
        }
    }

    res = pci_func_init_irqs(func);
    if(res) {
        pci_func_deinit_caps(func);
        ilist_remove(&device->function_list, &func->device_node);
        kfree(func);
        return res;
    }

    res = register_pci_func(func);
    if(res) {
        // TODO deinit bars
        // TODO deinit irqs
        pci_func_deinit_caps(func);
        ilist_remove(&device->function_list, &func->device_node);
        kfree(func);
        return res;
    }

    return 0;
}

