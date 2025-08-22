
#include <drivers/usb/transfer.h>

int
usb_transfer_init_struct(
        struct usb_transfer *xfer,
        struct usb_device *device,
        struct usb_transfer_ops *ops,
        usb_transfer_t type)
{
    xfer->device = device;
    xfer->ops = ops;
    xfer->type = type;

    xfer->callback = NULL;

    xfer->status = USB_TRANSFER_STATUS_IDLE;
    waitqueue_init(&xfer->status_waitqueue);

    return 0;
}

int
usb_transfer_deinit_struct(
        struct usb_transfer *xfer)
{
    waitqueue_disable(&xfer->status_waitqueue);
    wake_all(&xfer->status_waitqueue);
    waitqueue_deinit(&xfer->status_waitqueue);

    return 0;
}

int
usb_transfer_await(
        struct usb_transfer *xfer)
{
    int res;

    while(xfer->status != USB_TRANSFER_STATUS_COMPLETE) {
        if(xfer->status < 0) {
            return xfer->status;
        }
        res = wait_on(&xfer->status_waitqueue);
	if(res) {
	    // Weird but ignore it
	}
    }
    return 0;
}

int
usb_transfer_set_status(
        struct usb_transfer *xfer,
        int status)
{
    xfer->status = status;
    mbarrier();
    wake_all(&xfer->status_waitqueue);
    return 0;
}

