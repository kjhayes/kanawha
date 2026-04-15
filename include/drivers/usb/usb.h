#ifndef __KANAWHA__USB_USB_H__
#define __KANAWHA__USB_USB_H__

#include <kanawha/ops.h>
#include <drivers/usb/id.h>

struct usb_device;
struct usb_driver;

#define USB_DRIVER_PROBE_DEVICE_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_device *, device)

#define USB_DRIVER_CONFIGURE_DEVICE_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_device *, device)

#define USB_DRIVER_INIT_DEVICE_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_device *, device)

#define USB_DRIVER_DEINIT_DEVICE_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_device *, device)

#define USB_DRIVER_OP_LIST(OP,...)\
OP(probe, USB_DRIVER_PROBE_DEVICE_SIG, ##__VA_ARGS__)\
OP(configure, USB_DRIVER_CONFIGURE_DEVICE_SIG, ##__VA_ARGS__)\
OP(init_device, USB_DRIVER_INIT_DEVICE_SIG, ##__VA_ARGS__)\
OP(deinit_device, USB_DRIVER_DEINIT_DEVICE_SIG, ##__VA_ARGS__)\

struct usb_driver_ops {
    DECLARE_OP_LIST_PTRS(USB_DRIVER_OP_LIST, struct usb_driver *)
};

struct usb_driver
{
    struct usb_driver_ops *ops;

    ilist_node_t match_node;
};

DEFINE_OP_LIST_WRAPPERS(
        USB_DRIVER_OP_LIST,
        static inline,
        /* No Prefix */,
        usb_driver,
        OPS_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR)

int
register_usb_device(struct usb_device *device);
int
unregister_usb_device(struct usb_device *device);

int
register_usb_driver(struct usb_driver *driver);
int
unregister_usb_driver(struct usb_driver *driver);

#endif
