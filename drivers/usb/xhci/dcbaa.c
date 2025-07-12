
#include <drivers/usb/xhci/xhci.h>
#include <drivers/usb/xhci/dcbaa.h>
#include <drivers/usb/xhci/reg.h>
#include <kanawha/dma.h>
#include <kanawha/kmalloc.h>

int
usb_xhci_init_dcbaa(
        struct usb_xhci *dev)
{
    int res;
    res = dma_alloc(
            8*(dev->num_device_ctx+1),
            dev->page_order > 6 ? dev->page_order : 6,
            dev->is_64bit ? DMA_PHYS_64 : DMA_PHYS_32,
            &dev->dcbaa_dma);
    if(res) {
        return res;
    }

    dev->dcbaa = dma_virt_addr(dev->dcbaa_dma);
    memset(dev->dcbaa, 0, 8*(dev->num_device_ctx+1));

    if(dev->num_scratchpads > 0) {
        dma_free(dev->dcbaa_dma, 8*(dev->num_device_ctx+1));
        wprintk("USB XHCI Driver does not support scratchpads currently! (device requested %lu scratchpads)\n",
                (ul_t)dev->num_scratchpads);
        return -EINVAL;
    }

    usb_xhci_write(
            dev,
            DCBAAP,
            (uint64_t)dma_phys_addr(dev->dcbaa_dma)
            );

    usb_xhci_write(
            dev,
            MaxSlotsEn,
            dev->num_device_ctx);

    return 0;
}

int
usb_xhci_deinit_dcbaa(
        struct usb_xhci *dev)
{
    dev->dcbaa = NULL;
    dma_free(dev->dcbaa_dma, 8*(dev->num_device_ctx+1));
    return 0;
}

