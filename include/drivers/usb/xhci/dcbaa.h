#ifndef __KANAWHA__USB_XHCI_DCBAA_H__
#define __KANAWHA__USB_XHCI_DCBAA_H__

struct usb_xhci;

int
usb_xhci_init_dcbaa(
        struct usb_xhci *dev);
int
usb_xhci_deinit_dcbaa(
        struct usb_xhci *dev);

#endif
