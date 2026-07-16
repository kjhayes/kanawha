
#include <drivers/pci/bar.h>
#include <drivers/pci/irq.h>
#include <drivers/pci/pci.h>
#include <drivers/usb/xhci/cap.h>
#include <drivers/usb/xhci/command.h>
#include <drivers/usb/xhci/device.h>
#include <drivers/usb/xhci/event.h>
#include <drivers/usb/xhci/reg.h>
#include <drivers/usb/xhci/xhci.h>
#include <kanawha/dma.h>
#include <kanawha/endian.h>
#include <kanawha/init.h>
#include <kanawha/page_alloc.h>
#include <kanawha/types.h>

static void
usb_xhci_legacy_support_capability_mark_os_ownership(struct usb_xhci *xhci,
                                                     size_t cap_offset,
                                                     void *priv_state)
{
    printk("Marking USB XHCI Controller as OS Owned\n");
    pci_bar_writeb(&xhci->func->bars[0], cap_offset + 3, (uint8_t)1);
}

static void
usb_xhci_legacy_support_capability_check_for_bios_release(struct usb_xhci *xhci,
                                                          size_t cap_offset,
                                                          void *priv_state)
{
    int *res = priv_state;

    uint8_t bios_semaphore;
    bios_semaphore = pci_bar_readb(&xhci->func->bars[0], cap_offset + 2);
    if(bios_semaphore)
    {
        clk_delay(sec_to_duration(1));
        bios_semaphore = pci_bar_readb(&xhci->func->bars[0], cap_offset + 2);
        if(bios_semaphore)
        {
            *res = -ETIMEDOUT;
        }
    }
}

static int
usb_xhci_claim_from_bios(struct usb_xhci *dev)
{
    int res;

    usb_xhci_for_each_capability_of_type(
        dev,
        USB_XHCI_EXT_CAPABILITY_ID_USB_LEGACY_SUPPORT,
        usb_xhci_legacy_support_capability_mark_os_ownership,
        NULL);

    res = 0;
    usb_xhci_for_each_capability_of_type(
        dev,
        USB_XHCI_EXT_CAPABILITY_ID_USB_LEGACY_SUPPORT,
        usb_xhci_legacy_support_capability_check_for_bios_release,
        (void *)&res);

    if(res)
    {
        eprintk("BIOS refused to relinquish control of the USB XHCI "
                "controller!\n");
        return res;
    }

    return 0;
}

static int
usb_xhci_wait_for_ready(struct usb_xhci *dev)
{
#define USB_XHCI_READY_MAX_WAIT_SEC 2

    duration_t max_delay = sec_to_duration(USB_XHCI_READY_MAX_WAIT_SEC);
    duration_t cur_delay = 0;
    duration_t delay_step = nsec_to_duration(100);

    while(1)
    {
        if(!usb_xhci_read(dev, CNR))
        {
            break;
        }
        clk_delay(delay_step);
        cur_delay += delay_step;
        if(cur_delay >= max_delay)
        {
            wprintk("XHCI USB controller failed to get ready within %d "
                    "second(s)! (raising ETIMEDOUT)\n",
                    (int)USB_XHCI_READY_MAX_WAIT_SEC);
            return -ETIMEDOUT;
        }
    }

    return 0;
}

static int
usb_xhci_halt(struct usb_xhci *dev)
{
    int res;
    usb_xhci_write(dev, R_S, 0);

    res = usb_xhci_wait_for_ready(dev);
    if(res)
    {
        return res;
    }

    return 0;
}

static int
usb_xhci_reset(struct usb_xhci *dev)
{
    int res;
    usb_xhci_write(dev, HCRST, 1);

#define USB_XHCI_RESET_MAX_WAIT_SEC 2

    duration_t max_delay = sec_to_duration(USB_XHCI_RESET_MAX_WAIT_SEC);
    duration_t cur_delay = 0;
    duration_t delay_step = nsec_to_duration(100);

    while(usb_xhci_read(dev, HCRST))
    {
        clk_delay(delay_step);
        cur_delay += delay_step;
        if(cur_delay >= max_delay)
        {
            wprintk("Failed to reset XHCI USB controller within %d "
                    "seconds! "
                    "(raising ETIMEDOUT)\n",
                    (int)USB_XHCI_RESET_MAX_WAIT_SEC);
            return -ETIMEDOUT;
        }
    }

    res = usb_xhci_wait_for_ready(dev);
    if(res)
    {
        return res;
    }

    return 0;
}

static int
usb_xhci_resume(struct usb_xhci *dev)
{
    int res;
    usb_xhci_write(dev, R_S, 1);

#define USB_XHCI_RESUME_MAX_WAIT_SEC 2

    duration_t max_delay = sec_to_duration(USB_XHCI_RESUME_MAX_WAIT_SEC);
    duration_t cur_delay = 0;
    duration_t delay_step = nsec_to_duration(100);

    while(1)
    {
        if(!usb_xhci_read(dev, HCH))
        {
            break;
        }
        clk_delay(delay_step);
        cur_delay += delay_step;
        if(cur_delay >= max_delay)
        {
            wprintk("Failed to resume XHCI USB controller within %d "
                    "seconds! "
                    "(raising ETIMEDOUT)\n",
                    (int)USB_XHCI_RESUME_MAX_WAIT_SEC);
            return -ETIMEDOUT;
        }
    }

    return 0;
}

static int
usb_xhci_init_scratchpads(struct usb_xhci *dev)
{
    int res;

    printk("USB XHCI: requested %d scratchpads\n", dev->num_scratchpads);
    if(dev->num_scratchpads == 0)
    {
        dev->scratchpad_pages = NULL;
        return 0;
    }

    dev->scratchpad_pages =
        kzmalloc(sizeof(void __phys *) * dev->num_scratchpads, KM_KERNEL);
    if(dev->scratchpad_pages == NULL)
    {
        return -ENOMEM;
    }

    res = dma_alloc(sizeof(uint64_t) * dev->num_scratchpads,
                    6,
                    DMA_PHYS_64,
                    &dev->scratchpad_array);
    if(res)
    {
        kfree(dev->scratchpad_pages);
        dev->scratchpad_pages = NULL;
        return res;
    }

    void __phys **dma_virt = dma_virt_addr(dev->scratchpad_array);

    size_t num_allocated = 0;
    for(size_t i = 0; i < dev->num_scratchpads; i++)
    {
        void __phys *page;
        res = page_alloc(dev->page_order, &page, PAGE_ALLOC_64BIT);
        if(res)
        {
            break;
        }
        dev->scratchpad_pages[i] = page;
        dma_virt[i] = page;
        num_allocated++;
    }
    if(num_allocated != dev->num_scratchpads)
    {
        for(size_t i = 0; i < num_allocated; i++)
        {
            page_free(dev->page_order, dev->scratchpad_pages[i]);
        }
        kfree(dev->scratchpad_pages);
        dev->scratchpad_pages = NULL;
        dma_free(dev->scratchpad_array,
                 sizeof(uint64_t) * dev->num_scratchpads);
        return res;
    }
    return 0;
}

static int
usb_xhci_deinit_scratchpads(struct usb_xhci *dev)
{
    for(size_t i = 0; i < dev->num_scratchpads; i++)
    {
        page_free(dev->page_order, dev->scratchpad_pages[i]);
    }
    kfree(dev->scratchpad_pages);
    dma_free(dev->scratchpad_array, sizeof(uint64_t) * dev->num_scratchpads);
    return 0;
}

static int
usb_xhci_init_device_contextes(struct usb_xhci *dev)
{
    int res;

    irq_lock_init(&dev->devices_lock);

    struct usb_xhci_device **devices =
        kzmalloc(sizeof(struct usb_xhci_device *) * dev->num_device_ctx,
                 KM_KERNEL);
    if(devices == NULL)
    {
        return -ENOMEM;
    }

    res = dma_alloc(8 * (dev->num_device_ctx + 1),
                    dev->page_order > 6 ? dev->page_order : 6,
                    dev->is_64bit ? DMA_PHYS_64 : DMA_PHYS_32,
                    &dev->dcbaa_dma);
    if(res)
    {
        kfree(devices);
        return res;
    }

    dev->dcbaa = dma_virt_addr(dev->dcbaa_dma);
    memset(dev->dcbaa, 0, 8 * (dev->num_device_ctx + 1));

    if(dev->num_scratchpads > 0)
    {
        // Set up the pointer to the
        // scratchpad buffers
        DEBUG_ASSERT(KERNEL_ADDR(dev->scratchpad_pages));
        void __phys *scratchpad_array = dma_phys_addr(dev->scratchpad_array);
        dev->dcbaa->scratchpad_array_ptr = scratchpad_array;
    }

    dev->devices = devices;

    usb_xhci_write(dev, DCBAAP, (uint64_t)dma_phys_addr(dev->dcbaa_dma));

    usb_xhci_write(dev, MaxSlotsEn, dev->num_device_ctx);

    return 0;
}

static int
usb_xhci_deinit_device_contextes(struct usb_xhci *dev)
{
    for(size_t i = 0; i < dev->num_device_ctx; i++)
    {
        if(dev->devices[i] != NULL)
        {
            return -EBUSY;
        }
    }

    struct usb_xhci_device **devices = dev->devices;
    dev->devices = NULL;
    kfree(devices);

    dev->dcbaa = NULL;
    dma_free(dev->dcbaa_dma, 8 * (dev->num_device_ctx + 1));

    return 0;
}

static int
usb_xhci_probe(struct pci_driver *driver, struct pci_func *func)
{
    dprintk("usb_xhci_probe!\n");
    return 0;
}

static int
usb_xhci_init_device(struct pci_driver *driver, struct pci_func *func)
{
    int res;

    printk("USB XHCI found root hub on PCI bus\n");

    struct usb_xhci *dev = kzmalloc(sizeof(*dev), KM_KERNEL);
    if(dev == NULL)
    {
        return -ENOMEM;
    }

    dev->func = func;

    pci_func_raw_enable_mmio(dev->func);
    pci_func_raw_enable_bus_master(dev->func);

    res = usb_xhci_bootstrap_reg_access(dev);
    if(res)
    {
        eprintk("USB XHCI failed to bootstrap register access!\n");
        return res;
    }

    // Basic Info
    dev->page_order = usb_xhci_read(dev, PAGESIZE) + 12;
    dev->num_device_ctx = usb_xhci_read(dev, MaxSlots);
    dev->is_64bit = usb_xhci_read(dev, AC64);

    {
        size_t lo = usb_xhci_read(dev, Max_Scratchpad_Bufs_Lo);
        size_t high = usb_xhci_read(dev, Max_Scratchpad_Bufs_Hi);
        dev->num_scratchpads = (high << 5) | lo;
    }

    res = usb_xhci_claim_from_bios(dev);
    if(res)
    {
        kfree(dev);
        eprintk("USB XHCI failed to claim device from the BIOS!\n");
        return res;
    }

    res = usb_xhci_halt(dev);
    if(res)
    {
        kfree(dev);
        eprintk("USB XHCI failed to halt the root hub!\n");
        return res;
    }

    res = usb_xhci_reset(dev);
    if(res)
    {
        kfree(dev);
        eprintk("USB XHCI failed to reset the root hub!\n");
        return res;
    }

    res = usb_xhci_init_scratchpads(dev);
    if(res)
    {
        kfree(dev);
        eprintk("USB XHCI failed to initialize scratchpad pages!\n");
        return res;
    }

    res = usb_xhci_init_device_contextes(dev);
    if(res)
    {
        kfree(dev);
        eprintk("USB XHCI failed to initialize device contextes!\n");
        return res;
    }
    dprintk("initialized the device contextes!\n");

    res = usb_xhci_init_command_ring(dev, 255); // Single 4kb Page (probably)
    if(res)
    {
        usb_xhci_deinit_device_contextes(dev);
        usb_xhci_deinit_scratchpads(dev);
        kfree(dev);
        eprintk("USB XHCI failed to initialize command ring!\n");
        return res;
    }

    res = usb_xhci_init_ports(dev);
    if(res)
    {
        usb_xhci_deinit_command_ring(dev);
        usb_xhci_deinit_device_contextes(dev);
        usb_xhci_deinit_scratchpads(dev);
        kfree(dev);
        eprintk("Failed to init USB XHCI ports! (res=%s)\n", errnostr(res));
        return res;
    }

    res = usb_xhci_init_interruptors(dev);
    if(res)
    {
        usb_xhci_deinit_ports(dev);
        usb_xhci_deinit_command_ring(dev);
        usb_xhci_deinit_device_contextes(dev);
        usb_xhci_deinit_scratchpads(dev);
        kfree(dev);
        eprintk("Failed to init USB XHCI interruptors! (res=%s)\n",
                errnostr(res));
        return res;
    }

    res = usb_xhci_resume(dev);
    if(res)
    {
        usb_xhci_deinit_ports(dev);
        usb_xhci_deinit_interruptors(dev);
        usb_xhci_deinit_command_ring(dev);
        usb_xhci_deinit_device_contextes(dev);
        usb_xhci_deinit_scratchpads(dev);
        kfree(dev);
        eprintk("USB XHCI failed to resume root hub!\n");
        return res;
    }

    res = usb_xhci_start_command_ring(dev);
    if(res)
    {
        usb_xhci_deinit_ports(dev);
        usb_xhci_deinit_interruptors(dev);
        usb_xhci_deinit_command_ring(dev);
        usb_xhci_deinit_device_contextes(dev);
        usb_xhci_deinit_scratchpads(dev);
        kfree(dev);
        eprintk("USB XHCI failed to start command ring!\n");
        return res;
    }

    res = usb_xhci_reset_all_ports(dev);
    if(res)
    {
        eprintk("Failed to reset all USB ports on XHCI bringup!\n");
    }

    printk("USB Ports:\n");
    usb_xhci_dump_ports(dev, do_printk);

    //
    //    printk("USB Command Ring:\n");
    //    usb_xhci_dump_command_ring(do_printk, dev);

    printk("running noop command\n");
    res = usb_xhci_run_noop_command(dev);
    if(res)
    {
        usb_xhci_deinit_ports(dev);
        usb_xhci_deinit_interruptors(dev);
        usb_xhci_deinit_command_ring(dev);
        usb_xhci_deinit_device_contextes(dev);
        usb_xhci_deinit_scratchpads(dev);
        kfree(dev);
        eprintk("USB XHCI Failed to Respond to No-Op Command (res=%s)!\n",
                errnostr(res));
        return res;
    }

    printk("finished usb_xhci_init_device\n");
    return 0;
}

static int
usb_xhci_deinit_device(struct pci_driver *driver, struct pci_func *dev)
{
    eprintk("usb_xhci_deinit_device (UNIMPLEMENTED)\n");
    return -EUNIMPL;
}

static struct pci_id usb_xhci_pci_ids[] = {
    {
        .class = USB_XHCI_PCI_CLASS,
        .subclass = USB_XHCI_PCI_SUBCLASS,
        .prog_if = USB_XHCI_PCI_PROG_IF,
        .flags = PCI_ID_CHECK_CLASS | PCI_ID_CHECK_SUBCLASS |
                 PCI_ID_CHECK_PROG_IF | PCI_ID_IGNORE_VENDOR |
                 PCI_ID_IGNORE_DEVICE,
    },
};

static struct pci_driver_ops usb_xhci_pci_driver_ops = {
    .probe = &usb_xhci_probe,
    .init_device = &usb_xhci_init_device,
    .deinit_device = &usb_xhci_deinit_device,
};

static struct pci_driver usb_xhci_pci_driver = {
    .ops = &usb_xhci_pci_driver_ops,
    .num_ids = sizeof(usb_xhci_pci_ids) / sizeof(struct pci_id),
    .ids = usb_xhci_pci_ids,
};

DECLARE_PCI_DRIVER(usb_xhci_pci_driver);
