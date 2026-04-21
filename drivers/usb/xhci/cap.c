
#include <drivers/pci/bar.h>
#include <drivers/usb/xhci/cap.h>
#include <drivers/usb/xhci/reg.h>
#include <drivers/usb/xhci/xhci.h>

void
usb_xhci_for_each_capability_of_type(struct usb_xhci *xhci,
                                     uint8_t type,
                                     void (*callback)(struct usb_xhci *xhci,
                                                      size_t cap_offset,
                                                      void *priv_state),
                                     void *priv_state)

{
    size_t offset = usb_xhci_read(xhci, xECP);
    if(offset == 0)
    {
        return;
    }

    // xECP in is DWORD(s)
    offset *= 4;

    while(1)
    {
        le32_t le_value = pci_bar_readl(&xhci->func->bars[0], offset);

        uint32_t value = letoh32(le_value);
        uint8_t cur_type = value & 0xFF;
        printk("XHCI: EXT CAP TYPE(%d)\n", (int)cur_type);
        if(cur_type == type)
        {
            (*callback)(xhci, offset, priv_state);
        }

        uint8_t rel_offset = (value >> 8) & 0xFF;
        if(rel_offset == 0)
        {
            break;
        }

        offset += (rel_offset * 4); // Offsets are in DWORD(s)
    }
}
