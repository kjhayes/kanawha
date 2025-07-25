#ifndef __KANAWHA__USB_XHCI_PORT_H__
#define __KANAWHA__USB_XHCI_PORT_H__

#include <kanawha/types.h>
#include <kanawha/printk.h>

struct usb_xhci;

struct usb_xhci_port
{
    struct usb_xhci *xhci;
    size_t register_offset;

    struct tasklet *status_change_tasklet;
};

int
usb_xhci_init_ports(
        struct usb_xhci *xhci);
int
usb_xhci_deinit_ports(
        struct usb_xhci *xhci);

size_t
usb_xhci_port_index(
        struct usb_xhci_port *port);

int
usb_xhci_reset_all_ports(
        struct usb_xhci *xhci);

// To be called on the port when a PORT_STATUS_CHANGE event
// targeting it is received.
int
usb_xhci_port_notify_status_change(
        struct usb_xhci_port *port);

int
usb_xhci_dump_ports(
        struct usb_xhci *dev,
        printk_f *printer);

#endif
