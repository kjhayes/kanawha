
#include <drivers/usb/usb.h>
#include <drivers/usb/xhci/command.h>
#include <drivers/usb/xhci/ctx.h>
#include <drivers/usb/xhci/device.h>
#include <drivers/usb/xhci/endpoint.h>
#include <drivers/usb/xhci/reg.h>
#include <drivers/usb/xhci/xhci.h>
#include <kanawha/dma.h>
#include <kanawha/kmalloc.h>
#include <kanawha/page_alloc.h>
#include <kanawha/printk.h>
#include <kanawha/stddef.h>

#define USB_XHCI_CONTROL_TRANSFER_RING_SIZE 64

static inline int
usb_xhci_device_issue_disable_slot_command(struct usb_xhci_device *dev)
{
    int res;

    uint8_t trb_type = USB_XHCI_TRB_TYPE_ENABLE_SLOT_CMD;
    uint8_t slot_type = 0x0;

    uint64_t param = 0x0;
    uint32_t status = 0x0;
    uint32_t control = ((uint32_t)trb_type << 10) | ((uint32_t)slot_type << 16);
    res = usb_xhci_run_command(dev->xhci, &param, &status, &control);
    if(res)
    {
        wprintk("USB XHCI Failed to Run Disable Slot Command!\n");
        return res;
    }

    uint8_t cc = (status >> 24) & 0xFF;
    if(!usb_xhci_trb_completion_code_is_success(cc))
    {
        wprintk("USB XHCI Disable Slot Command Failed!\n");
        return -EINVAL;
    }

    return 0;
}

struct usb_xhci_device *
usb_xhci_create_device(struct usb_xhci *xhci)
{
    int res;

    struct usb_xhci_device *dev = kzmalloc(sizeof(*dev), KM_KERNEL);
    if(dev == NULL)
    {
        return NULL;
    }

    dev->xhci = xhci;
    dev->slot_index = 0; // Invalid slot
    irq_lock_init(&dev->endpoint_lock);
    memset(dev->endpoints, 0, sizeof(struct usb_xhci_endpoint *) * 31);
    irq_lock_init(&dev->registry_lock);
    dev->registered = 0; // This device has not been presented
                         // to the greater USB subsystem yet

    // Assign the device a slot

    {
        uint8_t trb_type = USB_XHCI_TRB_TYPE_ENABLE_SLOT_CMD;
        uint8_t slot_type = 0x0;

        uint64_t param = 0x0;
        uint32_t status = 0x0;
        uint32_t control =
            ((uint32_t)trb_type << 10) | ((uint32_t)slot_type << 16);
        res = usb_xhci_run_command(dev->xhci, &param, &status, &control);
        if(res)
        {
            wprintk("USB XHCI Failed to Run Enable Slot Command!\n");
            kfree(dev);
            return NULL;
        }

        uint8_t cc = (status >> 24) & 0xFF;
        if(usb_xhci_trb_completion_code_is_success(cc))
        {
            dev->slot_index = (control >> 24) & 0xFF;
        }
        else
        {
            dev->slot_index = 0;
        }
    }

    if(dev->slot_index == 0)
    {
        wprintk("USB XHCI Failed to obtain slot for device!\n");
        kfree(dev);
        return NULL;
    }

    DEBUG_ASSERT(KERNEL_ADDR(xhci->devices));
    DEBUG_ASSERT(xhci->devices[dev->slot_index - 1] == NULL);

    xhci->devices[dev->slot_index - 1] = dev;

    printk("USB XHCI: device assigned to slot %d\n", (int)dev->slot_index);

    // Allocate a device input context
    dev->input_ctx = usb_xhci_create_input_ctx(dev->xhci);
    if(dev->input_ctx == NULL) {
        usb_xhci_device_issue_disable_slot_command(dev);
        kfree(dev);
        return NULL; 
    }

    // Allocate a device context output
    dev->device_ctx = usb_xhci_create_device_ctx(dev->xhci);
    if(dev->device_ctx == NULL) {
        usb_xhci_destroy_input_ctx(dev->input_ctx);
        usb_xhci_device_issue_disable_slot_command(dev);
        kfree(dev);
        return NULL;
    }

    dprintk("XHCI: writing device context to DCBAA slot index %d\n", dev->slot_index-1);
    xhci->dcbaa->output_ctx_base_address[dev->slot_index - 1]
        = usb_xhci_device_ctx_phys_addr(dev->device_ctx);

    printk("USB XHCI: setup context for slot %d\n", (int)dev->slot_index);

    return dev;
}

int
usb_xhci_address_root_hub_device(struct usb_xhci_device *dev,
                                 struct usb_xhci_port *port)
{
    int res;

    // Set up the control transfer ring
    irq_lock_acquire(&dev->endpoint_lock);
    if(dev->endpoints[1] != NULL)
    {
        irq_lock_release(&dev->endpoint_lock);
        eprintk("usb_xhci_address_root_hub_device: control transfer ring is "
                "already setup!\n");
        return -EALREADY;
    }

    struct usb_xhci_endpoint *default_endpoint;
    default_endpoint =
        usb_xhci_create_endpoint(dev,
                                 USB_XHCI_CONTROL_TRANSFER_RING_SIZE,
                                 1 // Device Context Index 1
                );
    if(default_endpoint == NULL)
    {
        return -EINVAL;
    }

    dev->endpoints[1] = default_endpoint;
    irq_lock_release(&dev->endpoint_lock);

    size_t ctx_size = usb_xhci_input_ctx_entry_size(dev->input_ctx);

    dprintk("XHCI: ctx_entry_size = 0x%lx\n", ctx_size);

    usb_xhci_input_ctx_reset_add_drop(dev->input_ctx);
    usb_xhci_input_ctx_mark_add_ctx(dev->input_ctx, 0);
    usb_xhci_input_ctx_mark_add_ctx(dev->input_ctx, 1);

    struct usb_xhci_slot_ctx *slot_ctx;
    slot_ctx = usb_xhci_input_ctx_slot_ctx(dev->input_ctx);
    memset(slot_ctx, 0, ctx_size);

    slot_ctx->route_string = 0;
    slot_ctx->ctx_entries = 1;
    slot_ctx->root_hub_port_number = usb_xhci_port_index(port);
    slot_ctx->speed = usb_xhci_port_speed(port);

    dprintk("slot_ctx->root_hub_port_number=0x%lx\n",
            (ul_t)slot_ctx->root_hub_port_number);
    dprintk("slot_ctx->speed=0x%lx\n",
            (ul_t)slot_ctx->speed);

    struct usb_xhci_endpoint_ctx *endpoint_ctx;
    endpoint_ctx = usb_xhci_input_ctx_endpoint_ctx(dev->input_ctx, 1);
    memset(endpoint_ctx, 0, ctx_size);

    uintptr_t dequeue_ptr =
        (uintptr_t)usb_xhci_endpoint_get_transfer_ring_dequeue_pointer(default_endpoint);
    endpoint_ctx->endpoint_type = 4; // Control endpoint
    endpoint_ctx->error_count = 3; // Allow up to 3 retries
    endpoint_ctx->tr_dequeue_shifted_ptr = dequeue_ptr >> 4;
    endpoint_ctx->dequeue_cycle_state = 1;
    endpoint_ctx->avg_trb_length = 8;
    endpoint_ctx->interval = 0;

    uint32_t max_packet_size = 8;
    uint32_t max_burst_size = 0; // zero-coded
    uint32_t max_esit_payload = max_packet_size * (max_burst_size+1);

    endpoint_ctx->max_packet_size = max_packet_size;
    endpoint_ctx->max_burst_size  = max_burst_size;
    endpoint_ctx->max_esit_payload_hi = (max_burst_size >> 16) & 0xFF;
    endpoint_ctx->max_esit_payload_lo = max_burst_size & 0xFFFF;

    dprintk("slot_ctx=%p, ep0_ctx=%p\n", slot_ctx, endpoint_ctx);

    uint8_t trb_type = USB_XHCI_TRB_TYPE_ADDR_DEVICE_CMD;
    uint8_t slot_type = 0x0;
    uint8_t slot_index = dev->slot_index;

    uint64_t param = (uintptr_t)usb_xhci_input_ctx_phys_addr(dev->input_ctx);
    uint32_t status = 0x0;
    uint32_t control = ((uint32_t)trb_type << 10) |
                       ((uint32_t)slot_type << 16) |
                       ((uint32_t)slot_index << 24);
    res = usb_xhci_run_command(dev->xhci, &param, &status, &control);
    if(res)
    {
        wprintk("USB XHCI Failed to Run Address Device Command! (slotid=%d, "
                "portid=%d)\n",
                (int)dev->slot_index,
                (int)usb_xhci_port_index(port));
        return res;
    }

    uint8_t cc = (status >> 24) & 0xFF;
    if(!usb_xhci_trb_completion_code_is_success(cc))
    {
        wprintk("USB XHCI Address Device Command Failed! (slotid=%d, "
                "portid=%d) (err=%s)\n",
                (int)dev->slot_index,
                (int)usb_xhci_port_index(port),
                usb_xhci_trb_completion_code_to_string(cc));
        return -EINVAL;
    }

    return 0;
}

static struct usb_transfer *
usb_xhci_device_create_bulk_transfer(struct usb_device *usb_dev,
                                       usb_endpoint_id_t endpoint,
                                       void __phys *buffer,
                                       size_t buflen)
{
    uint8_t dci = usb_xhci_endpoint_id_to_dci(endpoint);

    struct usb_xhci_device *dev =
        container_of(usb_dev, struct usb_xhci_device, usb_device);
    struct usb_xhci_endpoint *endp = dev->endpoints[dci];
    if(endp == NULL)
    {
        return NULL;
    }

    struct usb_xhci_transfer *xfer;
    xfer = usb_xhci_endpoint_create_bulk_transfer(endp, buffer, buflen);
    if(xfer == NULL)
    {
        return NULL;
    }

    return &xfer->xfer;
}

static struct usb_transfer *
usb_xhci_device_create_control_transfer(struct usb_device *usb_dev,
                                            usb_endpoint_id_t endpoint,
                                            uint8_t bmRequestType,
                                            uint8_t bRequest,
                                            uint16_t wValue,
                                            uint16_t wIndex,
                                            uint16_t wLength,
                                            void __phys *buffer,
                                            size_t buflen
                                            )
{
    uint8_t dci = usb_xhci_endpoint_id_to_dci(endpoint);

    struct usb_xhci_device *dev =
        container_of(usb_dev, struct usb_xhci_device, usb_device);
    struct usb_xhci_endpoint *endp = dev->endpoints[dci];
    if(endp == NULL)
    {
        return NULL;
    }

    struct usb_xhci_transfer *xfer;
    xfer = usb_xhci_endpoint_create_control_transfer(endp,
                                                         bmRequestType,
                                                         bRequest,
                                                         wValue,
                                                         wIndex,
                                                         wLength,
                                                         buffer,
                                                         buflen);
    if(xfer == NULL)
    {
        return NULL;
    }

    return &xfer->xfer;
}

static struct usb_transfer *
usb_xhci_device_create_isoch_transfer(struct usb_device *usb_dev,
                                      usb_endpoint_id_t endpoint)
{
    uint8_t dci = usb_xhci_endpoint_id_to_dci(endpoint);

    struct usb_xhci_device *dev =
        container_of(usb_dev, struct usb_xhci_device, usb_device);
    struct usb_xhci_endpoint *endp = dev->endpoints[dci];
    if(endp == NULL)
    {
        return NULL;
    }

    struct usb_xhci_transfer *xfer;
    xfer = usb_xhci_endpoint_create_isoch_transfer(endp);
    if(xfer == NULL)
    {
        return NULL;
    }

    return &xfer->xfer;
}

static int
usb_xhci_device_destroy_transfer(struct usb_device *usb_dev,
                                 struct usb_transfer *gen_xfer)
{
    struct usb_xhci_device *dev =
        container_of(usb_dev, struct usb_xhci_device, usb_device);
    struct usb_xhci_transfer *xfer =
        container_of(gen_xfer, struct usb_xhci_transfer, xfer);
    return usb_xhci_destroy_transfer(xfer);
}

static struct usb_device_ops usb_xhci_device_ops = {
    .create_control_transfer = usb_xhci_device_create_control_transfer,
    .create_bulk_transfer = usb_xhci_device_create_bulk_transfer,
    .create_isoch_transfer = usb_xhci_device_create_isoch_transfer,
    .destroy_transfer = usb_xhci_device_destroy_transfer,
};

int
usb_xhci_register_root_hub_device(struct usb_xhci_device *dev)
{
    int res;

    irq_lock_acquire(&dev->registry_lock);

    if(dev->registered)
    {
        irq_lock_release(&dev->registry_lock);
        return -EALREADY;
    }

    res = usb_host_init_device(&dev->usb_device, &usb_xhci_device_ops);
    if(res)
    {
        irq_lock_release(&dev->registry_lock);
        return res;
    }

    res = register_usb_device(&dev->usb_device);
    if(res) {
        usb_host_deinit_device(&dev->usb_device);
        irq_lock_release(&dev->registry_lock);
        return res;
    }

    dev->registered = 1;

    irq_lock_release(&dev->registry_lock);
    return 0;
}

int
usb_xhci_destroy_device(struct usb_xhci_device *dev)
{
    int res;

    if(dev->registered)
    {
        usb_host_deinit_device(&dev->usb_device);
        unregister_usb_device(&dev->usb_device);
        dev->registered = 0;
    }

    // Disable the slot

    // First mark the slot as "free" on the software side,
    // otherwise we have a possible race condition, where
    // we free the slot, another device is assigned to the slot,
    // and the we incorrectly clear the "devices" array.
    dev->xhci->devices[dev->slot_index - 1] = NULL;

    mbarrier();

    for(size_t i = 0; i < 32; i++)
    {
        struct usb_xhci_endpoint *endp = dev->endpoints[i];
        if(endp != NULL)
        {
            res = usb_xhci_destroy_endpoint(endp);
            if(res)
            {
                wprintk("Failed to destroy USB endpoint on "
                        "device destruction! "
                        "(err=%s)\n",
                        errnostr(res));
            }
        }
    }

    res = usb_xhci_device_issue_disable_slot_command(dev);
    if(res)
    {
        wprintk("Failed to disable USB device slot on device destruction! "
                "(err=%s)\n",
                errnostr(res));
    }

    usb_xhci_destroy_input_ctx(dev->input_ctx);
    usb_xhci_destroy_device_ctx(dev->device_ctx);
    kfree(dev);
    return 0;
}

int
usb_xhci_device_notify_transfer_event(struct usb_xhci_device *dev,
                                      struct usb_xhci_trb *trb)
{
    int res;

    uint8_t endpoint = (trb->control >> 16) & 0x3F;

    irq_lock_acquire(&dev->endpoint_lock);

    struct usb_xhci_endpoint *endp = dev->endpoints[endpoint];
    if(endp == NULL)
    {
        irq_lock_release(&dev->endpoint_lock);
        return -ENXIO;
    }

    res = usb_xhci_endpoint_notify_transfer_event(endp, trb);
    if(res)
    {
        irq_lock_release(&dev->endpoint_lock);
        return res;
    }

    irq_lock_release(&dev->endpoint_lock);
    return 0;
}
