
#include <drivers/usb/xhci/xhci.h>
#include <drivers/usb/xhci/reg.h>
#include <drivers/usb/xhci/cap.h>
#include <drivers/pci/bar.h>

void
usb_xhci_for_each_capability_of_type(
        struct usb_xhci *xhci,
        uint8_t type,
        void(*callback)(
            struct usb_xhci *xhci,
            size_t cap_offset,
            void *priv_state),
        void *priv_state
        )

{
    size_t offset = usb_xhci_cap_reg_get_ext_cap_ptr(xhci);
    if(offset == 0) {
        return;
    }

    while(1)
    {
        le32_t le_value = pci_bar_readl(
                &xhci->func->bars[0],
                offset);

        uint32_t value = letoh32(le_value);
        uint8_t cur_type = value & 0xFF;
        if(cur_type == type) {
            (*callback)(
                    xhci,
                    offset,
                    priv_state);
        }

        uint8_t rel_offset = (value >> 8) & 0xFF;
        if(rel_offset == 0) {
            break;
        }

        offset += rel_offset;
    }
}

