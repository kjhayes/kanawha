
#include <kanawha/printk.h>
#include <kanawha/kmalloc.h>
#include <kanawha/dma.h>
#include <drivers/usb/xhci/device.h>
#include <drivers/usb/xhci/xhci.h>
#include <drivers/usb/xhci/slot.h>
#include <drivers/usb/xhci/command.h>
#include <drivers/usb/xhci/reg.h>

int
usb_xhci_init_device_contextes(
        struct usb_xhci *dev)
{
    int res;

    irq_lock_init(&dev->devices_lock);

    struct usb_xhci_device **devices = kmalloc(sizeof(struct usb_xhci_device*) * dev->num_device_ctx);
    if(devices == NULL) {
        return -ENOMEM;
    }
    memset(devices, 0, sizeof(struct usb_xhci_device*) * dev->num_device_ctx);

    res = dma_alloc(
            8*(dev->num_device_ctx+1),
            dev->page_order > 6 ? dev->page_order : 6,
            dev->is_64bit ? DMA_PHYS_64 : DMA_PHYS_32,
            &dev->dcbaa_dma);
    if(res) {
        kfree(devices);
        return res;
    }

    dev->dcbaa = dma_virt_addr(dev->dcbaa_dma);
    memset(dev->dcbaa, 0, 8*(dev->num_device_ctx+1));

    if(dev->num_scratchpads > 0) {
        dma_free(dev->dcbaa_dma, 8*(dev->num_device_ctx+1));
        wprintk("USB XHCI Driver does not support scratchpads currently! (device requested %lu scratchpads)\n",
                (ul_t)dev->num_scratchpads);
        kfree(devices);
        return -EINVAL;
    }

    dev->devices = devices;

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
usb_xhci_deinit_device_contextes(
        struct usb_xhci *dev)
{
    for(size_t i = 0; i < dev->num_device_ctx; i++) {
        if(dev->devices[i] != NULL) {
            return -EBUSY;
        }
    }

    struct usb_xhci_device **devices = dev->devices;
    dev->devices = NULL;
    kfree(devices);

    dev->dcbaa = NULL;
    dma_free(dev->dcbaa_dma, 8*(dev->num_device_ctx+1));

    return 0;
}

struct usb_xhci_device *
usb_xhci_create_device(
        struct usb_xhci *xhci)
{
    int res;

    struct usb_xhci_device *dev = kmalloc(sizeof(*dev));
    if(dev == NULL) {
        return NULL;
    }
    memset(dev, 0, sizeof(*dev));

    dev->xhci = xhci;
    dev->slot_index = 0; // Invalid slot
    dev->slot = NULL;

    // Assign the device a slot

    {
    uint8_t trb_type = USB_XHCI_TRB_TYPE_ENABLE_SLOT_CMD;
    uint8_t slot_type = 0x0;

    uint64_t param = 0x0;
    uint32_t status = 0x0;
    uint32_t control = ((uint32_t)trb_type << 10)
                     | ((uint32_t)slot_type << 16);
    res = usb_xhci_run_command(
            dev->xhci,
            &param,
            &status,
            &control);
    if(res) {
        wprintk("USB XHCI Failed to Run Enable Slot Command!\n");
        kfree(dev);
        return NULL;
    }

    uint8_t cc = (status >> 24) & 0xFF;
    if(usb_xhci_trb_completion_code_is_success(cc)) {
        dev->slot_index = (control >> 24) & 0xFF;
    } else {
        dev->slot_index = 0;
    }

    }

    if(dev->slot_index == 0) {
        wprintk("USB XHCI Failed to obtain slot for device!\n");
        kfree(dev);
        return NULL;
    }

    DEBUG_ASSERT(KERNEL_ADDR(xhci->devices));
    DEBUG_ASSERT(xhci->devices[dev->slot_index-1] == NULL);

    xhci->devices[dev->slot_index-1] = dev;

    printk("USB Device Assigned to Slot %d\n", (int)dev->slot_index);

    return dev;
}

int
usb_xhci_destroy_device(
        struct usb_xhci_device *dev)
{
    int res;

    // Disable the slot
    {
    // First mark the slot as "free" on the software side,
    // otherwise we have a possible race condition, where
    // we free the slot, another device is assigned to the slot,
    // and the we incorrectly clear the "devices" array.
    dev->xhci->devices[dev->slot_index-1] = NULL;
    mbarrier();

    uint8_t trb_type = USB_XHCI_TRB_TYPE_ENABLE_SLOT_CMD;
    uint8_t slot_type = 0x0;

    uint64_t param = 0x0;
    uint32_t status = 0x0;
    uint32_t control = ((uint32_t)trb_type << 10)
                     | ((uint32_t)slot_type << 16);
    res = usb_xhci_run_command(
            dev->xhci,
            &param,
            &status,
            &control);
    if(res) {
        wprintk("USB XHCI Failed to Run Disable Slot Command!\n");
        return res;
    }

    uint8_t cc = (status >> 24) & 0xFF;
    if(!usb_xhci_trb_completion_code_is_success(cc)) {
        wprintk("USB XHCI Disable Slot Command Failed!\n");
        return -EINVAL;
    }
    }

    kfree(dev);
    return 0;
}

