#ifndef __KANAWHA__USB_USB_H__
#define __KANAWHA__USB_USB_H__

#include <kanawha/ops.h>
#include <drivers/usb/id.h>

struct usb_device;
struct usb_interface;
struct usb_device_driver;
struct usb_interface_driver;

int
register_usb_device(struct usb_device *device);
int
unregister_usb_device(struct usb_device *device);

int
register_usb_interface(struct usb_interface *interface);
int
unregister_usb_interface(struct usb_interface *interface);


#define USB_DEVICE_DRIVER_PROBE_DEVICE_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_device *, device)

#define USB_DEVICE_DRIVER_CONFIGURE_DEVICE_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_device *, device)\
    ARG(size_t *, config_choice)

#define USB_DEVICE_DRIVER_INIT_DEVICE_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_device *, device)

#define USB_DEVICE_DRIVER_DEINIT_DEVICE_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_device *, device)

#define USB_DEVICE_DRIVER_OP_LIST(OP,...)\
OP(probe_device, USB_DEVICE_DRIVER_PROBE_DEVICE_SIG, ##__VA_ARGS__)\
OP(configure_device, USB_DEVICE_DRIVER_CONFIGURE_DEVICE_SIG, ##__VA_ARGS__)\
OP(init_device, USB_DEVICE_DRIVER_INIT_DEVICE_SIG, ##__VA_ARGS__)\
OP(deinit_device, USB_DEVICE_DRIVER_DEINIT_DEVICE_SIG, ##__VA_ARGS__)\

struct usb_device_driver_ops {
    DECLARE_OP_LIST_PTRS(USB_DEVICE_DRIVER_OP_LIST, struct usb_device_driver *)
};

struct usb_device_driver
{
    struct usb_device_driver_ops *ops;

    ilist_t matched_devices;

    ilist_node_t match_node;
};

DEFINE_OP_LIST_WRAPPERS(
        USB_DEVICE_DRIVER_OP_LIST,
        static inline,
        /* No Prefix */,
        usb_device_driver,
        OPS_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR)

int
register_usb_device_driver(struct usb_device_driver *driver);
int
unregister_usb_device_driver(struct usb_device_driver *driver);

#define USB_INTERFACE_DRIVER_PROBE_DEVICE_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_interface *, interface)

#define USB_INTERFACE_DRIVER_INIT_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_interface *, interface)

#define USB_INTERFACE_DRIVER_DEINIT_SIG(RET,ARG,...)\
    RET(int)\
    ARG(struct usb_interface *, interface)

#define USB_INTERFACE_DRIVER_OP_LIST(OP,...)\
OP(probe, USB_INTERFACE_DRIVER_PROBE_DEVICE_SIG, ##__VA_ARGS__)\
OP(init, USB_INTERFACE_DRIVER_INIT_SIG, ##__VA_ARGS__)\
OP(deinit, USB_INTERFACE_DRIVER_DEINIT_SIG, ##__VA_ARGS__)\

struct usb_interface_driver_ops {
    DECLARE_OP_LIST_PTRS(USB_INTERFACE_DRIVER_OP_LIST, struct usb_interface_driver *)
};

struct usb_interface_driver
{
    struct usb_interface_driver_ops *ops;

    ilist_t matched_interfaces;

    ilist_node_t match_node;
};

DEFINE_OP_LIST_WRAPPERS(
        USB_INTERFACE_DRIVER_OP_LIST,
        static inline,
        /* No Prefix */,
        usb_interface_driver,
        OPS_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR)

int
register_usb_interface_driver(struct usb_interface_driver *driver);
int
unregister_usb_interface_driver(struct usb_interface_driver *driver);

#endif
