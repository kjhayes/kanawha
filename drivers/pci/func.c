
#include <drivers/pci/cap.h>
#include <drivers/pci/cfg.h>
#include <drivers/pci/irq.h>
#include <drivers/pci/pci.h>
#include <kanawha/kmalloc.h>
#include <kanawha/mem_flags.h>
#include <kanawha/page_alloc.h>
#include <kanawha/string.h>
#include <kanawha/types.h>

static int
pci_setup_bars(struct pci_func *func)
{
    for(int i = 0; i < 6; i++)
    {
        struct pci_bar *bar = &func->bars[i];
        if(bar->type != PCI_BAR_UNINIT)
        {
            continue;
        }

        int bar_index = i;
        int upper_bar_index = i + 1;

        uint64_t original = (uint32_t)pci_func_raw_read_bar(func, bar_index);
        if(original & 1)
        {
            bar->type = PCI_BAR_PIO;
            pci_func_raw_enable_pio(func);
        }
        else
        {
            bar->type = PCI_BAR_MMIO;
            pci_func_raw_enable_mmio(func);
            bar->mmio.type = (original & 0x6ULL) >> 1;
            bar->mmio.prefetch = (original & 0x8ULL) >> 3;

            if(bar->mmio.type == 2)
            {

                original |=
                    (((uint64_t)pci_func_raw_read_bar(func, upper_bar_index))
                     << 32);

                i++; // Skip a BAR

                if(upper_bar_index >= 6)
                {
                    bar->type = PCI_BAR_NONE;
                    eprintk("PCI BAR 5 was marked as a "
                            "64-bit BAR!\n");
                    break;
                }
                func->bars[i].type = PCI_BAR_NONE; // Mark the upper
                                                   // half as "none"
            }
        }

        dprintk("original=0x%llx\n", (ull_t)original);
        pci_func_raw_write_bar(func, bar_index, 0xFFFFFFFFULL);
        uint64_t masked = pci_func_raw_read_bar(func, bar_index);
        if(bar->type == PCI_BAR_MMIO && bar->mmio.type == 2)
        {
            pci_func_raw_write_bar(func, upper_bar_index, 0xFFFFFFFFULL);
            uint64_t upper_masked =
                (uint64_t)pci_func_raw_read_bar(func, upper_bar_index);
            masked |= (upper_masked << 32);
        }

        dprintk("masked=0x%llx\n", (ull_t)masked);
        masked &= ~(bar->type == PCI_BAR_PIO ? 0x3ULL : 0xFULL);

        dprintk("masked=0x%llx\n", (ull_t)masked);
        uint64_t size_mask = 0xFFFFFFFFULL;
        if(bar->type == PCI_BAR_MMIO)
        {
            if(bar->mmio.type == 2)
            {
                size_mask = 0xFFFFFFFFFFFFFFFFULL;
            }
            else if(bar->mmio.type == 1)
            {
                size_mask = 0xFFFFULL;
            }
        }

        size_t size = (((~masked) & size_mask) + 1) & size_mask;
        dprintk("masked = %p, size_mask = %p, size = %p\n",
                (void *)masked,
                (void *)size_mask,
                (void *)size);

        pci_func_raw_write_bar(func, bar_index, (uint32_t)original);
        if(bar->type == PCI_BAR_MMIO && bar->mmio.type == 2)
        {
            pci_func_raw_write_bar(func,
                                   upper_bar_index,
                                   (uint32_t)(original >> 32));
        }

        if(size == 0)
        {
            memset(bar, 0, sizeof(struct pci_bar));
            bar->type = PCI_BAR_NONE;
            continue;
        }

        bar->size = size;

        if(bar->type == PCI_BAR_PIO)
        {
            bar->phys_addr = (void __phys *)(uintptr_t)(original & ~0x3ULL);
            bar->pio.base = (uintptr_t)(bar->phys_addr);

            pci_segment_set_pio_flags(func->segment,
                                      bar->pio.base,
                                      bar->size,
                                      PCI_PIO_MEM_MAPPED);
        }
        else
        {
            // MMIO
            bar->phys_addr = (void __phys *)(uintptr_t)(original & ~0xFULL);

#ifdef CONFIG_PCI_ALLOC_UNINITIALIZED_MMIO_BARS
            if(bar->phys_addr == 0)
            {
                int res;
                order_t order = ptr_orderof(bar->size);
                if(order < 12)
                {
                    order = 12;
                }
                int is_64_bit;
                if(bar->mmio.type == 2)
                {
                    // 64-bit bar
                    is_64_bit = 1;
                }
                else
                {
                    is_64_bit = 0;
                }
                uintptr_t reserved_base;
                res = mem_flags_find_and_reserve(
                    &func->segment->mmio_flags,
                    bar->size,
                    order,
                    PCI_MMIO_MEM_SNOOPED |
                        (is_64_bit ? 0 : PCI_MMIO_MEM_32_BIT),
                    // Must NOT be...
                    PCI_MMIO_MEM_MAPPED,
                    0,
                    PCI_MMIO_MEM_MAPPED,
                    &reserved_base);
                if(res)
                {
                    wprintk("Failed to remap uninitialized "
                            "PCI %d-bit MMIO BAR %ld of size 0x%lx! (err=%s)\n",
                            is_64_bit ? 64 : 32,
                            (sl_t)bar_index,
                            (ul_t)bar->size,
                            errnostr(res));
                    pci_segment_dump_mmio_mem_flags(func->segment, do_printk);
                    bar->phys_addr = 0;
                }
                else
                {
                    bar->phys_addr = (void __phys *)reserved_base;
                    pci_func_raw_write_bar(
                        func,
                        bar_index,
                        ((uint32_t)(uintptr_t)bar->phys_addr) |
                            (original & 0xFULL));
                    if(bar->mmio.type == 2)
                    {
                        pci_func_raw_write_bar(
                            func,
                            upper_bar_index,
                            (uint32_t)((uintptr_t)bar->phys_addr >> 32));
                    }
                    printk("Remapped Uninitialized PCI MMIO "
                           "BAR %ld to physical "
                           "addr=%p\n",
                           (sl_t)bar_index,
                           bar->phys_addr);
                }
            }
#endif
            if(bar->phys_addr != 0)
            {
                pci_segment_set_mmio_flags(func->segment,
                                           (uintptr_t)bar->phys_addr,
                                           bar->size,
                                           PCI_PIO_MEM_MAPPED);
                bar->mmio.base = mmio_map((void __phys *)bar->phys_addr, size);
                if(bar->mmio.base == NULL)
                {
                    eprintk("Failed to map PCI MMIO BAR "
                            "(phys_addr=%p) (err=%s)\n",
                            bar->phys_addr);
                    bar->type = PCI_BAR_NONE;
                    continue;
                }
            }
            else
            {
                eprintk("PCI MMIO BAR mapped to address zero!\n");
                bar->type = PCI_BAR_NONE;
                continue;
            }
            printk("Mapped MMIO PCI Bar to %p\n", bar->mmio.base);
        }
    }
    return 0;
}

int
pci_func_init(struct pci_func *func)
{
    int res;

    uint8_t hdr_type;
    pci_func_readb(func, PCI_CFG_HEADER_TYPE, &hdr_type);

    ilist_init(&func->cap_list);

    if((hdr_type & 0x7F) == PCI_HEADER_TYPE_DEVICE)
    {
#ifdef  CONFIG_PCI_SET_CACHE_LINE_SIZE
        pci_func_writeb(func, PCI_CFG_CACHE_LINE, CONFIG_PCI_CACHE_LINE_SIZE);
#endif /* CONFIG_PCI_SET_CACHE_LINE_SIZE */
        res = pci_setup_bars(func);
        if(res)
        {
            eprintk("Failed to initialize PCI device BAR(s)! (err=%s)\n",
                    errnostr(res));
            for(size_t i = 0; i < 6; i++)
            {
                func->bars[i].type = PCI_BAR_NONE;
            }
        }

        res = pci_func_init_caps(func);
        if(res)
        {
            eprintk("Failed to initialize PCI device capabilities! "
                    "(err=%s)\n",
                    errnostr(res));
        }
    }
    else
    {
        for(int i = 0; i < 6; i++)
        {
            func->bars[i].type = PCI_BAR_NONE;
        }
    }

    res = pci_func_init_irqs(func);
    if(res)
    {
        eprintk("Failed to initialize PCI device irqs! (err=%s)\n",
                errnostr(res));
    }

    return 0;
}

static int
pci_probe_bridge(struct pci_func *func)
{
    int res;

    uint8_t hdr_type;
    pci_func_readb(func, PCI_CFG_HEADER_TYPE, &hdr_type);

    if((hdr_type & 0x7F) == PCI_HEADER_TYPE_PCI_PCI_BRIDGE)
    {
        // Cross the PCI bridge
        uint8_t sec_bus;
        printk("Found PCI-to-PCI Bridge\n");
        pci_func_readb(func, PCI_CFG_PCI_BRIDGE_SECONDARY_BUS, &sec_bus);
        res = pci_probe_bus(func->device->bus->segment, sec_bus);
        if(res)
        {
            eprintk("Failed to enumerate secondary PCI bus %u of "
                    "segment %lu\n",
                    sec_bus,
                    func->segment->segment_id);
        }
    }

    return 0;
}

static int
pci_probe_bars(struct pci_func *func)
{
    for(int i = 0; i < 6; i++)
    {
        struct pci_bar bar = func->bars[i];
        if(bar.type != PCI_BAR_UNINIT)
        {
            continue;
        }

        int bar_index = i;
        int upper_bar_index = i + 1;

        uint64_t original = (uint32_t)pci_func_raw_read_bar(func, bar_index);
        if(original & 1)
        {
            bar.type = PCI_BAR_PIO;
        }
        else
        {
            bar.type = PCI_BAR_MMIO;
            bar.mmio.type = (original & 0x6ULL) >> 1;
            bar.mmio.prefetch = (original & 0x8ULL) >> 3;

            if(bar.mmio.type == 2)
            {

                original |=
                    (((uint64_t)pci_func_raw_read_bar(func, upper_bar_index))
                     << 32);

                i++; // Skip a BAR

                if(upper_bar_index >= 6)
                {
                    eprintk("pci_probe_bars: PCI BAR 5 was marked as a "
                            "64-bit BAR!\n");
                    break;
                }
            }
        }

        pci_func_raw_write_bar(func, bar_index, 0xFFFFFFFFULL);
        uint64_t masked = pci_func_raw_read_bar(func, bar_index);
        if(bar.type == PCI_BAR_MMIO && bar.mmio.type == 2)
        {
            pci_func_raw_write_bar(func, upper_bar_index, 0xFFFFFFFFULL);
            uint64_t upper_masked =
                (uint64_t)pci_func_raw_read_bar(func, upper_bar_index);
            masked |= (upper_masked << 32);
        }

        masked &= ~(bar.type == PCI_BAR_PIO ? 0x3ULL : 0xFULL);

        uint64_t size_mask = 0xFFFFFFFFULL;
        if(bar.type == PCI_BAR_MMIO)
        {
            if(bar.mmio.type == 2)
            {
                size_mask = 0xFFFFFFFFFFFFFFFFULL;
            }
            else if(bar.mmio.type == 1)
            {
                size_mask = 0xFFFFULL;
            }
        }

        size_t size = (((~masked) & size_mask) + 1) & size_mask;
        dprintk("masked = %p, size_mask = %p, size = %p\n",
                (void *)masked,
                (void *)size_mask,
                (void *)size);

        pci_func_raw_write_bar(func, bar_index, (uint32_t)original);
        if(bar.type == PCI_BAR_MMIO && bar.mmio.type == 2)
        {
            pci_func_raw_write_bar(func,
                                   upper_bar_index,
                                   (uint32_t)(original >> 32));
        }

        if(size == 0)
        {
            continue;
        }

        bar.size = size;

        if(bar.type == PCI_BAR_PIO)
        {
            bar.phys_addr = (void __phys *)(uintptr_t)(original & ~0x3ULL);
            bar.pio.base = (uintptr_t)(bar.phys_addr);

            pci_segment_set_pio_flags(func->segment,
                                      bar.pio.base,
                                      bar.size,
                                      PCI_PIO_MEM_MAPPED);
        }
        else
        {
            // MMIO
            bar.phys_addr = (void __phys *)(uintptr_t)(original & ~0xFULL);
            if(bar.phys_addr != 0)
            {
                pci_segment_set_mmio_flags(func->segment,
                                           (uintptr_t)bar.phys_addr,
                                           bar.size,
                                           PCI_PIO_MEM_MAPPED);
            }
        }
    }
    return 0;
}

int
pci_probe_func(struct pci_device *device, uint8_t index)
{
    int res;

    struct pci_bus *bus = device->bus;

    struct pci_func *func = NULL;
    struct ptree_node *device_tree_node =
        ptree_get(&device->function_tree, index);
    if(device_tree_node != NULL)
    {
        func = container_of(device_tree_node, struct pci_func, device_node);
    }

    uint16_t vendor_id;
    pci_bus_readw(bus, device->index, index, PCI_CFG_VENDOR_ID, &vendor_id);
    if(vendor_id == 0xFFFF)
    {
        if(func != NULL)
        {
            panic("PCI Function Stopped Existing on Re-probe!\n");
        }
        return -ENXIO;
    }

    if(func == NULL)
    {
        func = kzmalloc(sizeof(struct pci_func), KM_KERNEL);
        if(func == NULL)
        {
            eprintk("Failed to allocate PCI device struct!\n");
            return -ENOMEM;
        }

        func->segment = bus->segment;
        func->index = index;

        ptree_insert(&device->function_tree, &func->device_node, index);
        func->device = device;

        for(size_t i = 0; i < 6; i++)
        {
            func->bars[i].type = PCI_BAR_UNINIT;
        }

        for(int i = 0; i < 4; i++) {
            func->intx_routing[i] = NULL_IRQ;
        }
    }

    pci_bus_readw(bus,
                  device->index,
                  index,
                  PCI_CFG_VENDOR_ID,
                  &func->vendor_id);
    pci_bus_readw(bus,
                  device->index,
                  index,
                  PCI_CFG_DEVICE_ID,
                  &func->device_id);
    pci_bus_readb(bus, device->index, index, PCI_CFG_CLASS, &func->class_id);
    pci_bus_readb(bus,
                  device->index,
                  index,
                  PCI_CFG_SUBCLASS,
                  &func->subclass_id);
    pci_bus_readb(bus,
                  device->index,
                  index,
                  PCI_CFG_PROG_IF,
                  &func->prog_if_id);

    printk("PCI Function: %d.%d -> ID(%x:%x)\n",
           device->index,
           index,
           func->vendor_id,
           func->device_id);

    pci_probe_bridge(func);
    pci_probe_bars(func);

    return 0;
}
