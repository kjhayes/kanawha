#ifndef __KANAWHA__USB_ID_H__
#define __KANAWHA__USB_ID_H__

#include <kanawha/types.h>

struct usb_id {
    uint8_t class;
    uint8_t subclass;
    uint8_t protocol;
};

const char *
usb_id_class_name(
        struct usb_id *id);

const char *
usb_id_subclass_name(
        struct usb_id *id);

const char *
usb_id_protocol_name(
        struct usb_id *id);

#endif
