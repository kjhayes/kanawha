#ifndef __KANAWHA__USB_TRANSFER_H__
#define __KANAWHA__USB_TRANSFER_H__

#include <kanawha/ops.h>
#include <kanawha/waitqueue.h>

struct usb_transfer;

typedef enum
{
    USB_TRANSFER_CONTROL,
    USB_TRANSFER_BULK,
    USB_TRANSFER_ISOCH,
} usb_transfer_t;

#define USB_TRANSFER_LAUNCH_SIG(RET, ARG, ...) RET(int)

#define USB_TRANSFER_OP_LIST(OP, ...)                                          \
    OP(launch, USB_TRANSFER_LAUNCH_SIG, ##__VA_ARGS__)

struct usb_transfer_ops
{
    DECLARE_OP_LIST_PTRS(USB_TRANSFER_OP_LIST, struct usb_transfer *);
};

#define USB_TRANSFER_STATUS_IDLE (0)
#define USB_TRANSFER_STATUS_LAUNCHED (1)
#define USB_TRANSFER_STATUS_COMPLETE (2)

struct usb_transfer
{
    struct usb_device *device;
    usb_transfer_t type;

    irq_lock_t status_lock;
    int status;
    struct waitqueue status_waitqueue;

    void (*callback)(struct usb_transfer *);

    struct usb_transfer_ops *ops;
};

int
usb_transfer_init_struct(struct usb_transfer *xfer,
                         struct usb_device *device,
                         struct usb_transfer_ops *ops,
                         usb_transfer_t type);

int
usb_transfer_deinit_struct(struct usb_transfer *xfer);

DEFINE_OP_LIST_WRAPPERS(USB_TRANSFER_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        usb_transfer,
                        OPS_STRUCT_PTR_ACCESSOR,
                        SELF_ACCESSOR)

int
usb_transfer_await(struct usb_transfer *xfer);

int
usb_transfer_set_status(struct usb_transfer *xfer, int status);

#endif
