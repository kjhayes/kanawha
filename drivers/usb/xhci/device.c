
#include <kanawha/printk.h>
#include <drivers/usb/xhci/device.h>
#include <drivers/usb/xhci/xhci.h>
#include <drivers/usb/xhci/slot.h>
#include <drivers/usb/xhci/command.h>

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

    printk("USB Device Assigned to Slot %d\n", (int)dev->slot_index);

    return dev;
}

int
usb_xhci_destroy_device(
        struct usb_xhci_device *dev)
{
    kfree(dev);
    return 0;
}

