
#include <drivers/usb/xhci/reg.h>
#include <drivers/usb/xhci/xhci.h>

int
usb_xhci_bootstrap_reg_access(
        struct usb_xhci *xhci)
{
    xhci->op_reg_offset = usb_xhci_read(xhci, CAPLENGTH);
    xhci->port_reg_offset = 0x400;
    xhci->doorbell_offset = usb_xhci_read(xhci, DBOFF);
    xhci->runtime_reg_offset = usb_xhci_read(xhci, RTSOFF);

    return 0;
}



