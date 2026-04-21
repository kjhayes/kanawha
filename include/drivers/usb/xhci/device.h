#ifndef __KANAWHA__USB_XHCI_DEVICE_H__
#define __KANAWHA__USB_XHCI_DEVICE_H__

#include <drivers/usb/device.h>
#include <drivers/usb/xhci/ctx.h>
#include <drivers/usb/xhci/endpoint.h>
#include <drivers/usb/xhci/xhci.h>

struct usb_xhci_device
{
    struct usb_xhci *xhci;
    ilist_t xhci_list_node;

    size_t slot_index; // Indexed from 1

    struct usb_xhci_input_ctx *input_ctx;
    struct usb_xhci_device_ctx *device_ctx;

    irq_lock_t endpoint_lock;
    struct usb_xhci_endpoint *endpoints[31];

    // Host Controller Agnostic Device
    irq_lock_t registry_lock;
    int registered;
    struct usb_device usb_device;
};

struct usb_xhci;

struct __packed usb_xhci_dcbaa
{
    void __phys *scratchpad_array_ptr;
    void __phys *output_ctx_base_address[];
};
ASSERT_FIELD_OFFSET(struct usb_xhci_dcbaa, output_ctx_base_address, 8);
ASSERT_FIELD_OFFSET(struct usb_xhci_dcbaa, output_ctx_base_address[2], 24);

struct usb_xhci_device *
usb_xhci_create_device(struct usb_xhci *xhci);

int
usb_xhci_destroy_device(struct usb_xhci_device *dev);

int
usb_xhci_address_root_hub_device(struct usb_xhci_device *dev,
                                 struct usb_xhci_port *port);

int
usb_xhci_register_root_hub_device(struct usb_xhci_device *dev);

int
usb_xhci_device_notify_transfer_event(struct usb_xhci_device *dev,
                                      struct usb_xhci_trb *trb);

#endif
