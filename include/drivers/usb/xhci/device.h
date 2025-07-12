#ifndef __KANAWHA__USB_XHCI_DEVICE_H__
#define __KANAWHA__USB_XHCI_DEVICE_H__

#include <drivers/usb/xhci/xhci.h>
#include <drivers/usb/xhci/slot.h>

int
usb_xhci_init_device_contextes(
        struct usb_xhci *dev);
int
usb_xhci_deinit_device_contextes(
        struct usb_xhci *dev);

struct usb_xhci_device
{
    struct usb_xhci *xhci;
    ilist_t xhci_list_node;

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
