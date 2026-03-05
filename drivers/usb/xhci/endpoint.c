
#include <drivers/usb/xhci/endpoint.h>
#include <drivers/usb/xhci/reg.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

struct usb_xhci_endpoint *
usb_xhci_create_endpoint(struct usb_xhci_device *dev,
                         size_t tr_size,
                         size_t dci)
{
    int res;

    struct usb_xhci_endpoint *ep;
    ep = kzmalloc(sizeof(*ep), KM_KERNEL);
    if(ep == NULL)
    {
        return NULL;
    }

    ep->device = dev;
    ep->dci = dci;
    irq_lock_init(&ep->lock);
    ilist_init(&ep->transfer_queue);

    res = usb_xhci_init_trb_ring(dev->xhci, &ep->ring, 255);
    if(res)
    {
        kfree(ep);
        return NULL;
    }

    return ep;
}

int
usb_xhci_destroy_endpoint(struct usb_xhci_endpoint *endp)
{
    usb_xhci_deinit_trb_ring(&endp->ring);
    kfree(endp);
    return 0;
}

void
usb_xhci_endpoint_ring_doorbell(struct usb_xhci_endpoint *endp)
{
    uint16_t task = 0;
    uint8_t target = endp->dci;

    usb_xhci_write_doorbell(endp->device->xhci,
                            endp->device->slot_index,
                            target,
                            task);
}

int
usb_xhci_endpoint_notify_transfer_event(struct usb_xhci_endpoint *endp,
                                        struct usb_xhci_trb *trb)
{
    void __phys *dequeued = (void __phys *)(uintptr_t)letoh64(trb->param);
    endp->ring.dequeue_phys = dequeued;

    irq_lock_acquire(&endp->lock);
    ilist_node_t *node = ilist_pop_head(&endp->transfer_queue);

    struct usb_xhci_transfer *xfer =
        container_of(node, struct usb_xhci_transfer, endpoint_queue_node);

    xfer->xfer.status = USB_TRANSFER_STATUS_COMPLETE;
    if(xfer->xfer.callback != NULL)
    {
        xfer->xfer.callback(&xfer->xfer);
    }

    irq_lock_release(&endp->lock);

    return 0;
}

static int
usb_xhci_normal_transfer_launch(struct usb_transfer *gen_xfer)
{
    struct usb_xhci_transfer *xfer =
        container_of(gen_xfer, struct usb_xhci_transfer, xfer);
    irq_lock_acquire(&xfer->endpoint->lock);

    if(xfer->xfer.status != USB_TRANSFER_STATUS_IDLE)
    {
        irq_lock_release(&xfer->endpoint->lock);
        return -EALREADY;
    }

    // TODO

    // ilist_push_tail(&xfer->endpoint->transfer_queue,
    // &xfer->endpoint_queue_node);
    usb_transfer_set_status(&xfer->xfer, USB_TRANSFER_STATUS_LAUNCHED);

    irq_lock_release(&xfer->endpoint->lock);
    return -EUNIMPL;
}

static struct usb_transfer_ops usb_xhci_normal_transfer_ops = {
    .launch = usb_xhci_normal_transfer_launch,
};

static int
usb_xhci_setup_stage_transfer_launch(struct usb_transfer *gen_xfer)
{
    int res;

    struct usb_xhci_transfer *xfer =
        container_of(gen_xfer, struct usb_xhci_transfer, xfer);

    irq_lock_acquire(&xfer->endpoint->lock);

    if(xfer->xfer.status != USB_TRANSFER_STATUS_IDLE)
    {
        irq_lock_release(&xfer->endpoint->lock);
        return -EALREADY;
    }

    struct usb_xhci_trb *trb;
    res = usb_xhci_trb_ring_get_avail_trbs(&xfer->endpoint->ring, &trb, 1);
    if(res)
    {
        irq_lock_release(&xfer->endpoint->lock);
        return res;
    }

    xfer->final_trb = trb;

    uint64_t param;
    uint32_t status;
    uint32_t control;

    param = (((uint64_t)xfer->setup_stage.bmRequestType) << 0) |
            (((uint64_t)xfer->setup_stage.bRequest) << 8) |
            (((uint64_t)xfer->setup_stage.wValue) << 16) |
            (((uint64_t)xfer->setup_stage.wIndex) << 32) |
            (((uint64_t)xfer->setup_stage.wLength) << 48);

    uint16_t interruptor = 0; // Target Zero No Matter What For Now
    status = 0x8 << ((uint32_t)interruptor << 22);

    control = (1ULL << 5) | // IOC
              (1ULL << 6) | // IDT
              (USB_XHCI_TRB_TYPE_SETUP_STAGE << 10) |
              (xfer->setup_stage.trt << 16);

    trb->param = htole64(param);
    trb->status = htole32(status);
    // Write Control Without Changing the Enqueue Pointer Bit
    trb->control =
        (htole32(control & ~0b1) & ~0b1) | (trb->control & htole32(0b1));

    ilist_push_tail(&xfer->endpoint->transfer_queue,
                    &xfer->endpoint_queue_node);
    usb_transfer_set_status(&xfer->xfer, USB_TRANSFER_STATUS_LAUNCHED);

    res = usb_xhci_trb_ring_advance_enqueued(&xfer->endpoint->ring, 1);
    if(res)
    {
        usb_transfer_set_status(&xfer->xfer, res);
        ilist_remove(&xfer->endpoint->transfer_queue,
                     &xfer->endpoint_queue_node);
        irq_lock_release(&xfer->endpoint->lock);
        return 0;
    }

    usb_xhci_endpoint_ring_doorbell(xfer->endpoint);

    irq_lock_release(&xfer->endpoint->lock);
    return 0;
}

static struct usb_transfer_ops usb_xhci_setup_stage_transfer_ops = {
    .launch = usb_xhci_setup_stage_transfer_launch,
};

static int
usb_xhci_data_stage_transfer_launch(struct usb_transfer *gen_xfer)
{
    struct usb_xhci_transfer *xfer =
        container_of(gen_xfer, struct usb_xhci_transfer, xfer);
    irq_lock_acquire(&xfer->endpoint->lock);

    if(xfer->xfer.status != USB_TRANSFER_STATUS_IDLE)
    {
        irq_lock_release(&xfer->endpoint->lock);
        return -EALREADY;
    }

    // TODO

    // ilist_push_tail(&xfer->endpoint->transfer_queue,
    // &xfer->endpoint_queue_node);
    usb_transfer_set_status(&xfer->xfer, USB_TRANSFER_STATUS_LAUNCHED);

    irq_lock_release(&xfer->endpoint->lock);
    return -EUNIMPL;
}

static struct usb_transfer_ops usb_xhci_data_stage_transfer_ops = {
    .launch = usb_xhci_data_stage_transfer_launch,
};

static int
usb_xhci_status_stage_transfer_launch(struct usb_transfer *gen_xfer)
{
    struct usb_xhci_transfer *xfer =
        container_of(gen_xfer, struct usb_xhci_transfer, xfer);
    irq_lock_acquire(&xfer->endpoint->lock);

    if(xfer->xfer.status != USB_TRANSFER_STATUS_IDLE)
    {
        irq_lock_release(&xfer->endpoint->lock);
        return -EALREADY;
    }

    // TODO

    // ilist_push_tail(&xfer->endpoint->transfer_queue,
    // &xfer->endpoint_queue_node);
    usb_transfer_set_status(&xfer->xfer, USB_TRANSFER_STATUS_LAUNCHED);

    irq_lock_release(&xfer->endpoint->lock);
    return -EUNIMPL;
}

static struct usb_transfer_ops usb_xhci_status_stage_transfer_ops = {
    .launch = usb_xhci_status_stage_transfer_launch,
};

static int
usb_xhci_isoch_transfer_launch(struct usb_transfer *gen_xfer)
{
    struct usb_xhci_transfer *xfer =
        container_of(gen_xfer, struct usb_xhci_transfer, xfer);
    irq_lock_acquire(&xfer->endpoint->lock);

    if(xfer->xfer.status != USB_TRANSFER_STATUS_IDLE)
    {
        irq_lock_release(&xfer->endpoint->lock);
        return -EALREADY;
    }

    // TODO

    // ilist_push_tail(&xfer->endpoint->transfer_queue,
    // &xfer->endpoint_queue_node);
    usb_transfer_set_status(&xfer->xfer, USB_TRANSFER_STATUS_LAUNCHED);

    irq_lock_release(&xfer->endpoint->lock);
    return -EUNIMPL;
}

static struct usb_transfer_ops usb_xhci_isoch_transfer_ops = {
    .launch = usb_xhci_isoch_transfer_launch,
};

struct usb_xhci_transfer *
usb_xhci_alloc_transfer(struct usb_xhci_endpoint *endp, usb_transfer_t type)
{
    struct usb_xhci_transfer *xfer;
    xfer = kzmalloc(sizeof(*xfer), KM_KERNEL);
    if(xfer == NULL)
    {
        return NULL;
    }
    xfer->endpoint = endp;

    struct usb_transfer_ops *ops;
    switch(type)
    {
    case USB_TRANSFER_NORMAL:
        ops = &usb_xhci_normal_transfer_ops;
        break;
    case USB_TRANSFER_SETUP_STAGE:
        ops = &usb_xhci_setup_stage_transfer_ops;
        break;
    case USB_TRANSFER_DATA_STAGE:
        ops = &usb_xhci_data_stage_transfer_ops;
        break;
    case USB_TRANSFER_STATUS_STAGE:
        ops = &usb_xhci_status_stage_transfer_ops;
        break;
    case USB_TRANSFER_ISOCH:
        ops = &usb_xhci_isoch_transfer_ops;
        break;

    default:
        kfree(xfer);
        return NULL;
    }
    usb_transfer_init_struct(&xfer->xfer, &endp->device->usb_device, ops, type);

    return xfer;
}

int
usb_xhci_free_transfer(struct usb_xhci_transfer *xfer)
{
    usb_transfer_deinit_struct(&xfer->xfer);
    kfree(xfer);
    return 0;
}

struct usb_xhci_transfer *
usb_xhci_endpoint_create_normal_transfer(struct usb_xhci_endpoint *endp,
                                         void __phys *buffer,
                                         size_t buflen)
{
    struct usb_xhci_transfer *xfer =
        usb_xhci_alloc_transfer(endp, USB_TRANSFER_NORMAL);

    xfer->normal.buffer = buffer;
    xfer->normal.buflen = buflen;

    return xfer;
}

struct usb_xhci_transfer *
usb_xhci_endpoint_create_setup_stage_transfer(struct usb_xhci_endpoint *endp,
                                              uint8_t bmRequestType,
                                              uint8_t bRequest,
                                              uint16_t wValue,
                                              uint16_t wIndex,
                                              uint16_t wLength,
                                              int trt)
{
    struct usb_xhci_transfer *xfer =
        usb_xhci_alloc_transfer(endp, USB_TRANSFER_SETUP_STAGE);

    xfer->setup_stage.bmRequestType = bmRequestType;
    xfer->setup_stage.bRequest = bRequest;
    xfer->setup_stage.wValue = wValue;
    xfer->setup_stage.wIndex = wIndex;
    xfer->setup_stage.wLength = wLength;
    xfer->setup_stage.trt = trt;

    return xfer;
}

struct usb_xhci_transfer *
usb_xhci_endpoint_create_data_stage_transfer(struct usb_xhci_endpoint *endp,
                                             void __phys *buffer,
                                             size_t buflen,
                                             int dir)
{
    struct usb_xhci_transfer *xfer =
        usb_xhci_alloc_transfer(endp, USB_TRANSFER_DATA_STAGE);

    xfer->data_stage.buffer = buffer;
    xfer->data_stage.buflen = buflen;
    xfer->data_stage.dir = dir;

    return xfer;
}

struct usb_xhci_transfer *
usb_xhci_endpoint_create_status_stage_transfer(struct usb_xhci_endpoint *endp,
                                               int dir)
{
    struct usb_xhci_transfer *xfer =
        usb_xhci_alloc_transfer(endp, USB_TRANSFER_STATUS_STAGE);

    xfer->status_stage.dir = dir;

    return xfer;
}

struct usb_xhci_transfer *
usb_xhci_endpoint_create_isoch_transfer(struct usb_xhci_endpoint *endp)
{
    struct usb_xhci_transfer *xfer =
        usb_xhci_alloc_transfer(endp, USB_TRANSFER_ISOCH);

    // TODO actually write the isoch API

    return xfer;
}

int
usb_xhci_destroy_transfer(struct usb_xhci_transfer *xfer)
{
    int res;

    res = usb_xhci_free_transfer(xfer);
    if(res)
    {
        return res;
    }

    return 0;
}
