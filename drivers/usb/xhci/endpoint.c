
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

    dprintk("endpoint_ring_doorbell: dci=0x%lx\n",
            (ul_t)target);

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
    ilist_node_t *node = ilist_peek_head(&endp->transfer_queue);
    if(node == NULL) {
        eprintk("usb_xhci_endpoint_notify_transfer_event: No transfer is in progress!\n");
        irq_lock_release(&endp->lock);
        return -ENXIO;
    }

    struct usb_xhci_transfer *xfer =
        container_of(node, struct usb_xhci_transfer, endpoint_queue_node);

    if(xfer->final_trb != dequeued) {
        // This is not the final TRB of the transfer
        wprintk("usb_xhci_transfer: partial notification of transfer... (final=%p, dequeued=%p)",
                xfer->final_trb, dequeued);
        irq_lock_release(&endp->lock);
        return 0;
    }

    ilist_pop_head(&endp->transfer_queue);

    usb_transfer_set_status(&xfer->xfer, USB_TRANSFER_STATUS_COMPLETE);
    if(xfer->xfer.callback != NULL)
    {
        xfer->xfer.callback(&xfer->xfer);
    }

    irq_lock_release(&endp->lock);

    return 0;
}

static int
usb_xhci_control_transfer_launch(struct usb_transfer *gen_xfer)
{
    int res;

    struct usb_xhci_transfer *xfer =
        container_of(gen_xfer, struct usb_xhci_transfer, xfer);

    // HACK: We don't support large buffers yet
    if((xfer->control.buflen & 0x1FFFF) != xfer->control.buflen) {
        return -ENOMEM;
    }

    irq_lock_acquire(&xfer->endpoint->lock);

    if(xfer->xfer.status != USB_TRANSFER_STATUS_IDLE)
    {
        irq_lock_release(&xfer->endpoint->lock);
        return -EALREADY;
    }

    size_t num_data_trbs = (xfer->control.buflen  > 0);
    size_t num_event_trbs = 0;
    size_t num_trbs = 2 + num_data_trbs + num_event_trbs;

    struct usb_xhci_trb *trbs[num_trbs];
    res = usb_xhci_trb_ring_get_avail_trbs(
            &xfer->endpoint->ring,
            trbs,
            &xfer->final_trb,
            num_trbs);
    if(res)
    {
        irq_lock_release(&xfer->endpoint->lock);
        return res;
    }

    uint32_t interruptor = 0; // Target Zero No Matter What For Now

    int dir_in = !!(xfer->control.bmRequestType & USB_DEV_CONTROL_REQUEST_TYPE_DIR_DEVICE_TO_HOST);

    { // Setup Stage
        struct usb_xhci_trb *trb = trbs[0];

        uint64_t param;
        uint32_t status;
        uint32_t control;

        uint32_t trt = 0;
        if(xfer->control.buflen == 0) {
            trt = 0;
        }
        else if(dir_in) {
            trt = 3;
        } else {
            trt = 2;
        }

        param = (((uint64_t)xfer->control.bmRequestType) << 0) |
                (((uint64_t)xfer->control.bRequest) << 8) |
                (((uint64_t)xfer->control.wValue) << 16) |
                (((uint64_t)xfer->control.wIndex) << 32) |
                (((uint64_t)xfer->control.wLength) << 48);

        status = 0x8 | ((uint32_t)interruptor << 22);

        control = 0
                  |(1ULL << 6) // IDT
                  |((uint32_t)USB_XHCI_TRB_TYPE_SETUP_STAGE << 10)
                  |(trt << 16)
                  ;

        control |= (letoh32(trb->control) & 0b1); // Keep the same cycle bit

        trb->param = htole64(param);
        trb->status = htole32(status);
        trb->control = htole32(control);
    }
    { // Data Stage
        if(num_data_trbs > 0)
        {
            struct usb_xhci_trb *trb = trbs[1];

            uint64_t param = 0;
            uint32_t status = 0;
            uint32_t control = 0;

            param |= (uintptr_t)xfer->control.buffer;

            size_t td_size = 0; // TODO change this if we ever
                                //      support more than one buffer

            status |= (xfer->control.buflen & 0x1FFFF)
                | ((uint32_t)(td_size & 0x1F) << 17)
                | ((uint32_t)interruptor << 22);

            control |= 0
                |((uint32_t)(num_data_trbs > 1) << 4) // Set the chain bit if we have multiple TRB(s)
                |(((uint32_t)USB_XHCI_TRB_TYPE_DATA_STAGE) << 10) // TRB Type
                |((uint32_t)dir_in << 16)
                ;

            control |= (letoh32(trb->control) & 0b1); // Keep the same cycle bit

            trb->param = htole64(param);
            trb->status = htole32(status);
            trb->control = htole32(control);

            ASSERT(num_data_trbs == 1);
            for(size_t i = 1; i < num_data_trbs; i++) {
                // Handle additional "normal TRB's" for
                // fragmented data... (Not Implemented)
                struct usb_xhci_trb *additional_trb = trbs[i + 1];
            }
        }
    }
    { // Status Stage
        struct usb_xhci_trb *trb = trbs[1 + num_data_trbs];
        uint64_t param = 0;
        uint32_t status = 0;
        uint32_t control = 0;

        int status_is_input;
        if(xfer->control.buflen == 0) {
            status_is_input = 1;
        } else if(dir_in) {
            status_is_input = 0;
        } else {
            status_is_input = 1;
        }

        status |= ((uint32_t)interruptor << 22);
        control |= 0
            |(1ULL << 5) // IOC
            |((uint32_t)USB_XHCI_TRB_TYPE_STATUS_STAGE << 10)
            |((uint32_t)status_is_input << 16)
            ;

        control |= (letoh32(trb->control) & 0b1); // Keep the same cycle bit

        trb->param = htole64(param);
        trb->status = htole32(status);
        trb->control = htole32(control);
    }

    ilist_push_tail(&xfer->endpoint->transfer_queue,
                    &xfer->endpoint_queue_node);

    usb_transfer_set_status(&xfer->xfer, USB_TRANSFER_STATUS_LAUNCHED);

    res = usb_xhci_trb_ring_advance_enqueued(&xfer->endpoint->ring, num_trbs);
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

static int
usb_xhci_bulk_transfer_launch(struct usb_transfer *gen_xfer)
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
    // usb_transfer_set_status(&xfer->xfer, USB_TRANSFER_STATUS_LAUNCHED);

    irq_lock_release(&xfer->endpoint->lock);
    return -EUNIMPL;
}

static struct usb_transfer_ops usb_xhci_bulk_transfer_ops = {
    .launch = usb_xhci_bulk_transfer_launch,
};


static struct usb_transfer_ops usb_xhci_control_transfer_ops = {
    .launch = usb_xhci_control_transfer_launch,
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
    // usb_transfer_set_status(&xfer->xfer, USB_TRANSFER_STATUS_LAUNCHED);

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
    case USB_TRANSFER_CONTROL:
        ops = &usb_xhci_control_transfer_ops;
        break;
    case USB_TRANSFER_BULK:
        ops = &usb_xhci_bulk_transfer_ops;
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
usb_xhci_endpoint_create_control_transfer(struct usb_xhci_endpoint *endp,
                                              uint8_t bmRequestType,
                                              uint8_t bRequest,
                                              uint16_t wValue,
                                              uint16_t wIndex,
                                              uint16_t wLength,
                                              void __phys *buffer,
                                              size_t buflen)
{
    struct usb_xhci_transfer *xfer =
        usb_xhci_alloc_transfer(endp, USB_TRANSFER_CONTROL);

    xfer->control.bmRequestType = bmRequestType;
    xfer->control.bRequest = bRequest;
    xfer->control.wValue = wValue;
    xfer->control.wIndex = wIndex;
    xfer->control.wLength = wLength;
    xfer->control.buffer = buffer;
    xfer->control.buflen = buflen;

    return xfer;
}

struct usb_xhci_transfer *
usb_xhci_endpoint_create_bulk_transfer(struct usb_xhci_endpoint *endp,
                                         void __phys *buffer,
                                         size_t buflen)
{
    struct usb_xhci_transfer *xfer =
        usb_xhci_alloc_transfer(endp, USB_TRANSFER_BULK);

    xfer->bulk.buffer = buffer;
    xfer->bulk.buflen = buflen;

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
