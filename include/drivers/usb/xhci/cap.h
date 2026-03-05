#ifndef __KANAWHA__USB_XHCI_CAP_H__
#define __KANAWHA__USB_XHCI_CAP_H__

#include <kanawha/types.h>

struct usb_xhci;

#define USB_XHCI_EXT_CAPABILITY_ID_USB_LEGACY_SUPPORT (1)

void
usb_xhci_for_each_capability_of_type(struct usb_xhci *xhci,
                                     uint8_t type,
                                     void (*callback)(struct usb_xhci *xhci,
                                                      size_t cap_offset,
                                                      void *priv_state),
                                     void *priv_state);

#endif
