#ifndef __KANAWHA__USB_DEVICE_H__
#define __KANAWHA__USB_DEVICE_H__

#include <drivers/usb/transfer.h>
#include <kanawha/ops.h>

struct usb_device;

#define USB_DEV_CREATE_NORMAL_TRANSFER_SIG(RET, ARG, ...)                      \
    RET(struct usb_transfer *)                                                 \
    ARG(int, dci)                                                              \
    ARG(void __phys *, buffer)                                                 \
    ARG(size_t, buflen)

#define USB_DEV_CREATE_CONTROL_TRANSFER_SIG(RET, ARG, ...)                 \
    RET(struct usb_transfer *)                                                 \
    ARG(int, dci)                                                              \
    ARG(uint8_t, bmRequestType)                                                \
    ARG(uint8_t, bRequest)                                                     \
    ARG(uint16_t, wValue)                                                      \
    ARG(uint16_t, wIndex)                                                      \
    ARG(uint16_t, wLength)                                                     \
    ARG(void __phys *, buffer) \
    ARG(size_t, buflen)

#define USB_DEV_CREATE_ISOCH_TRANSFER_SIG(RET, ARG, ...)                       \
    RET(struct usb_transfer *)                                                 \
    ARG(int, dci)

#define USB_DEV_DESTROY_TRANSFER_SIG(RET, ARG, ...)                            \
    RET(int)                                                                   \
    ARG(struct usb_transfer *, xfer)

#define USB_DEV_OP_LIST(OP, ...)                                               \
    OP(create_normal_transfer,                                                 \
       USB_DEV_CREATE_NORMAL_TRANSFER_SIG,                                     \
       ##__VA_ARGS__)                                                          \
    OP(create_control_transfer,                                            \
       USB_DEV_CREATE_CONTROL_TRANSFER_SIG,                                \
       ##__VA_ARGS__)                                                          \
    OP(create_isoch_transfer,                                                  \
       USB_DEV_CREATE_ISOCH_TRANSFER_SIG,                                      \
       ##__VA_ARGS__)                                                          \
    OP(destroy_transfer, USB_DEV_DESTROY_TRANSFER_SIG, ##__VA_ARGS__)

// Operations provided by the host controller
struct usb_device_ops
{
    DECLARE_OP_LIST_PTRS(USB_DEV_OP_LIST, struct usb_device *);
};

struct usb_device
{
    struct usb_device_ops *ops;

    ilist_node_t match_node;
};

DEFINE_OP_LIST_WRAPPERS(USB_DEV_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        usb_device,
                        OPS_STRUCT_PTR_ACCESSOR,
                        SELF_ACCESSOR)

#undef USB_DEV_CREATE_NORMAL_TRANSFER_SIG
#undef USB_DEV_CREATE_CONTROL_TRANSFER_SIG
#undef USB_DEV_CREATE_ISOCH_TRANSFER_SIG
#undef USB_DEV_DESTROY_TRANSFER_SIG
#undef USB_DEV_OP_LIST

int
usb_host_init_device(struct usb_device *device, struct usb_device_ops *ops);

int
usb_host_deinit_device(struct usb_device *device);

#define USB_DEV_CONTROL_REQUEST_TYPE_DIR_HOST_TO_DEVICE (0b0 << 7)
#define USB_DEV_CONTROL_REQUEST_TYPE_DIR_DEVICE_TO_HOST (0b1 << 7)
#define USB_DEV_CONTROL_REQUEST_TYPE_STANDARD (0b00 << 5)
#define USB_DEV_CONTROL_REQUEST_TYPE_CLASS (0b01 << 5)
#define USB_DEV_CONTROL_REQUEST_TYPE_VENDOR (0b10 << 5)
#define USB_DEV_CONTROL_REQUEST_TYPE_TARGET_DEVICE (0b00000 << 0)
#define USB_DEV_CONTROL_REQUEST_TYPE_TARGET_INTERFACE (0b00001 << 0)
#define USB_DEV_CONTROL_REQUEST_TYPE_TARGET_ENDPOINT (0b00010 << 0)
#define USB_DEV_CONTROL_REQUEST_TYPE_TARGET_OTHER (0b00011 << 0)

#define USB_DEV_CONTROL_REQUEST_GET_STATUS (0x00)
#define USB_DEV_CONTROL_REQUEST_CLEAR_FEATURE (0x01)
#define USB_DEV_CONTROL_REQUEST_SET_FEATURE (0x03)
#define USB_DEV_CONTROL_REQUEST_SET_ADDRESS (0x05)
#define USB_DEV_CONTROL_REQUEST_GET_DESCRIPTOR (0x06)
#define USB_DEV_CONTROL_REQUEST_SET_DESCRIPTOR (0x07)
#define USB_DEV_CONTROL_REQUEST_GET_CONFIGURATION (0x08)
#define USB_DEV_CONTROL_REQUEST_SET_CONFIGURATION (0x09)
#define USB_DEV_CONTROL_REQUEST_GET_INTERFACE (0x0A)
#define USB_DEV_CONTROL_REQUEST_SET_INTERFACE (0x11)
#define USB_DEV_CONTROL_REQUEST_SYNC_FRAME (0x12)

int
usb_device_control_transfer(struct usb_device *device,
                            int dci,
                            uint8_t bmRequestType,
                            uint8_t bRequest,
                            uint16_t wValue,
                            uint16_t wIndex,
                            uint16_t wLength,
                            void __phys *buffer,
                            size_t bufsize);

#endif
