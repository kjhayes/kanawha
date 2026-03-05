
#define KEEP_USB_XHCI_TRB_COMPLETION_CODE_XLIST
#define KEEP_USB_XHCI_TRB_TYPE_XLIST
#include <drivers/usb/xhci/trb.h>

int
usb_xhci_trb_get_cycle(struct usb_xhci_trb *trb)
{
    return (trb->control & 0b1);
}
void
usb_xhci_trb_set_cycle(struct usb_xhci_trb *trb, int value)
{
    trb->control = (trb->control & ~0b1) | (!!value);
}
void
usb_xhci_trb_toggle_cycle(struct usb_xhci_trb *trb, int value)
{
    trb->control = (trb->control ^ 0b1);
}

uint8_t
usb_xhci_trb_get_type(struct usb_xhci_trb *trb)
{
    return (trb->control >> 10) & 0x3F;
}
void
usb_xhci_trb_set_type(struct usb_xhci_trb *trb, uint8_t value)
{
    trb->control = (trb->control & ~(0x3F << 10)) | ((value & 0x3F) << 10);
}

static int
usb_xhci_trb_completion_code_is_vendor_error(uint8_t type)
{
    return (type >= 192 && type <= 223);
}
static int
usb_xhci_trb_completion_code_is_vendor_info(uint8_t type)
{
    return (type >= 224 && type <= 255);
}

int
usb_xhci_trb_completion_code_is_success(uint8_t value)
{
    return value == USB_XHCI_TRB_COMPLETION_CODE_SUCCESS ||
           usb_xhci_trb_completion_code_is_vendor_info(value);
}

const char *
usb_xhci_trb_completion_code_to_string(uint8_t type)
{
    switch(type)
    {
#define CASE(__NAME, __VAL)                                                    \
    case __VAL:                                                                \
        return #__NAME;
        USB_XHCI_TRB_COMPLETION_CODE_XLIST(CASE)
#undef CASE
    default:
        if(usb_xhci_trb_completion_code_is_vendor_error(type))
        {
            return "VENDOR-DEFINED-ERROR";
        }
        else if(usb_xhci_trb_completion_code_is_vendor_info(type))
        {
            return "VENDOR-DEFINED-INFO";
        }
        else
        {
            return "UNKNOWN";
        }
    }
}

const char *
usb_xhci_trb_type_to_string(uint8_t type)
{
    switch(type)
    {
#define CASE(__NAME, __VAL)                                                    \
    case __VAL:                                                                \
        return #__NAME;
        USB_XHCI_TRB_TYPE_XLIST(CASE)
#undef CASE
    default:
        return "UNKNOWN";
    }
}
