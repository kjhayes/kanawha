#ifndef __KANAWHA__USB_XHCI_DEVICE_H__
#define __KANAWHA__USB_XHCI_DEVICE_H__

#include <drivers/usb/xhci/xhci.h>
#include <drivers/usb/xhci/slot.h>

struct usb_xhci_device
{
    struct usb_xhci *xhci;

    size_t slot_index; // Indexed from 1

    dma_addr_t slot_dma_buffer;
    struct usb_xhci_device_ctx *slot;
};

struct usb_xhci_device *
usb_xhci_create_device(
        struct usb_xhci *xhci);

int
usb_xhci_destroy_device(
        struct usb_xhci_device *dev);

#endif
