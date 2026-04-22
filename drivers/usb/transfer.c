
#include <drivers/usb/transfer.h>

int
usb_transfer_init_struct(struct usb_transfer *xfer,
                         struct usb_device *device,
                         struct usb_transfer_ops *ops,
                         usb_transfer_t type)
{
    int res;

    xfer->device = device;
    xfer->ops = ops;
    xfer->type = type;

    xfer->callback = NULL;

    irq_lock_init(&xfer->status_lock);
    xfer->status = USB_TRANSFER_STATUS_IDLE;
    res = waitqueue_init(&xfer->status_waitqueue);
    if(res)
    {
        return res;
    }

    char *name = "usb-transfer";
    switch(xfer->type)
    {
    case USB_TRANSFER_CONTROL:
        name = "usb-control-transfer";
        break;
    case USB_TRANSFER_BULK:
        name = "usb-bulk-transfer";
        break;
    case USB_TRANSFER_ISOCH:
        name = "usb-isoch-transfer";
        break;
    }

    waitqueue_name(&xfer->status_waitqueue, name);

    return 0;
}

int
usb_transfer_deinit_struct(struct usb_transfer *xfer)
{
    waitqueue_disable(&xfer->status_waitqueue);
    wake_all(&xfer->status_waitqueue);
    waitqueue_deinit(&xfer->status_waitqueue);

    return 0;
}

int
usb_transfer_await(struct usb_transfer *xfer)
{
    int res;

    irq_lock_acquire(&xfer->status_lock);
    while(xfer->status != USB_TRANSFER_STATUS_COMPLETE)
    {
        if(xfer->status < 0)
        {
            irq_lock_release(&xfer->status_lock);
            return xfer->status;
        }
        if(xfer->status == USB_TRANSFER_STATUS_IDLE)
        {
            return -EINVAL;
        }
        int irq_flags;
        res = wait_on_irq_lock_release(&xfer->status_waitqueue,
                                       &xfer->status_lock,
                                       &irq_flags);
        enable_restore_irqs(irq_flags);
        if(res == -EINTR)
        {
            // We cannot continue blocking if we
            // are interrupted
            return res;
        }
        irq_lock_acquire(&xfer->status_lock);
    }
    irq_lock_release(&xfer->status_lock);
    return 0;
}

int
usb_transfer_set_status(struct usb_transfer *xfer, int status)
{
    irq_lock_acquire(&xfer->status_lock);
    xfer->status = status;
    mbarrier();
    wake_all(&xfer->status_waitqueue);
    irq_lock_release(&xfer->status_lock);
    return 0;
}
