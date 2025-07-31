
#include <kanawha/printk.h>
#include <kanawha/kmalloc.h>
#include <kanawha/dma.h>
#include <kanawha/stddef.h>
#include <drivers/usb/xhci/device.h>
#include <drivers/usb/xhci/ctx.h>
#include <drivers/usb/xhci/xhci.h>
#include <drivers/usb/xhci/command.h>
#include <drivers/usb/xhci/reg.h>
#include <drivers/usb/xhci/endpoint.h>

#define USB_XHCI_CONTROL_TRANSFER_RING_SIZE 64

static inline int
usb_xhci_device_issue_disable_slot_command(
        struct usb_xhci_device *dev)
{
    int res;

    uint8_t trb_type = USB_XHCI_TRB_TYPE_ENABLE_SLOT_CMD;
    uint8_t slot_type = 0x0;

    uint64_t param = 0x0;
    uint32_t status = 0x0;
    uint32_t control = ((uint32_t)trb_type << 10)
                     | ((uint32_t)slot_type << 16);
    res = usb_xhci_run_command(
            dev->xhci,
            &param,
            &status,
            &control);
    if(res) {
        wprintk("USB XHCI Failed to Run Disable Slot Command!\n");
        return res;
    }

    uint8_t cc = (status >> 24) & 0xFF;
    if(!usb_xhci_trb_completion_code_is_success(cc)) {
        wprintk("USB XHCI Disable Slot Command Failed!\n");
        return -EINVAL;
    }

    return 0;
}

int
usb_xhci_init_device_contextes(
        struct usb_xhci *dev)
{
    int res;

    irq_lock_init(&dev->devices_lock);

    struct usb_xhci_device **devices = kzmalloc(sizeof(struct usb_xhci_device*) * dev->num_device_ctx, KM_KERNEL);
    if(devices == NULL) {
        return -ENOMEM;
    }

    res = dma_alloc(
            8*(dev->num_device_ctx+1),
            dev->page_order > 6 ? dev->page_order : 6,
            dev->is_64bit ? DMA_PHYS_64 : DMA_PHYS_32,
            &dev->dcbaa_dma);
    if(res) {
        kfree(devices);
        return res;
    }

    dev->dcbaa = dma_virt_addr(dev->dcbaa_dma);
    memset(dev->dcbaa, 0, 8*(dev->num_device_ctx+1));

    if(dev->num_scratchpads > 0) {
        dma_free(dev->dcbaa_dma, 8*(dev->num_device_ctx+1));
        wprintk("USB XHCI Driver does not support scratchpads currently! (device requested %lu scratchpads)\n",
                (ul_t)dev->num_scratchpads);
        kfree(devices);
        return -EINVAL;
    }

    dev->devices = devices;

    usb_xhci_write(
            dev,
            DCBAAP,
            (uint64_t)dma_phys_addr(dev->dcbaa_dma)
            );

    usb_xhci_write(
            dev,
            MaxSlotsEn,
            dev->num_device_ctx);

    return 0;
}

int
usb_xhci_deinit_device_contextes(
        struct usb_xhci *dev)
{
    for(size_t i = 0; i < dev->num_device_ctx; i++) {
        if(dev->devices[i] != NULL) {
            return -EBUSY;
        }
    }

    struct usb_xhci_device **devices = dev->devices;
    dev->devices = NULL;
    kfree(devices);

    dev->dcbaa = NULL;
    dma_free(dev->dcbaa_dma, 8*(dev->num_device_ctx+1));

    return 0;
}

struct usb_xhci_device *
usb_xhci_create_device(
        struct usb_xhci *xhci)
{
    int res;

    struct usb_xhci_device *dev = kzmalloc(sizeof(*dev), KM_KERNEL);
    if(dev == NULL) {
        return NULL;
    }

    dev->xhci = xhci;
    dev->slot_index = 0; // Invalid slot
    irq_lock_init(&dev->endpoint_lock);
    memset(dev->endpoints, 0, sizeof(struct usb_xhci_endpoint*) * 31);
    irq_lock_init(&dev->registry_lock);
    dev->registered = 0; // This device has not been presented
                         // to the greater USB subsystem yet

    // Assign the device a slot

    {
    uint8_t trb_type = USB_XHCI_TRB_TYPE_ENABLE_SLOT_CMD;
    uint8_t slot_type = 0x0;

    uint64_t param = 0x0;
    uint32_t status = 0x0;
    uint32_t control = ((uint32_t)trb_type << 10)
                     | ((uint32_t)slot_type << 16);
    res = usb_xhci_run_command(
            dev->xhci,
            &param,
            &status,
            &control);
    if(res) {
        wprintk("USB XHCI Failed to Run Enable Slot Command!\n");
        kfree(dev);
        return NULL;
    }

    uint8_t cc = (status >> 24) & 0xFF;
    if(usb_xhci_trb_completion_code_is_success(cc)) {
        dev->slot_index = (control >> 24) & 0xFF;
    } else {
        dev->slot_index = 0;
    }

    }

    if(dev->slot_index == 0) {
        wprintk("USB XHCI Failed to obtain slot for device!\n");
        kfree(dev);
        return NULL;
    }

    DEBUG_ASSERT(KERNEL_ADDR(xhci->devices));
    DEBUG_ASSERT(xhci->devices[dev->slot_index-1] == NULL);

    xhci->devices[dev->slot_index-1] = dev;

    printk("USB Device Assigned to Slot %d\n", (int)dev->slot_index);

    // Allocate a device context output

    dev->ctx_size = usb_xhci_read(dev->xhci, CSZ) ? 64 : 32;

    res = dma_alloc(
            dev->ctx_size * 32,
            4, // 16-byte aligned
            usb_xhci_read(dev->xhci, AC64) ? DMA_PHYS_64 : DMA_PHYS_32,
            &dev->slot_dma_buffer);
    if(res) {
        usb_xhci_device_issue_disable_slot_command(dev);
        kfree(dev);
        return NULL;
    }

    void *buffer = dma_virt_addr(dev->slot_dma_buffer);
    memset(buffer, 0, dev->ctx_size * 32);

    void __phys *phys_buffer = dma_phys_addr(dev->slot_dma_buffer);
    xhci->dcbaa->output_ctx_base_address[dev->slot_index-1] = phys_buffer;

    return dev;
}

int
usb_xhci_address_root_hub_device(
        struct usb_xhci_device *dev,
        struct usb_xhci_port *port)
{
    int res;

    // Set up the control transfer ring
    irq_lock_acquire(&dev->endpoint_lock);
    if(dev->endpoints[1] != NULL) {
        irq_lock_release(&dev->endpoint_lock);
        return -EALREADY;
    }

    struct usb_xhci_endpoint *default_endpoint;
    default_endpoint = usb_xhci_create_endpoint(
            dev,
            1, // Device Context Index 1
            USB_XHCI_CONTROL_TRANSFER_RING_SIZE);
    if(default_endpoint == NULL) {
        return -EINVAL;
    }

    dev->endpoints[1] = default_endpoint;
    irq_lock_release(&dev->endpoint_lock);

    struct usb_xhci_input_ctx *input_ctx;
    input_ctx = usb_xhci_create_input_ctx(dev->xhci);
    if(input_ctx == NULL) {
        return -ENOMEM;
    }

    size_t ctx_size = usb_xhci_input_ctx_entry_size(input_ctx);

    struct usb_xhci_slot_ctx *slot_ctx = usb_xhci_input_ctx_add_ctx(input_ctx, 0);
    if(slot_ctx == NULL) {
        usb_xhci_destroy_input_ctx(input_ctx);
        return -EINVAL;
    }
    memset(slot_ctx, 0, ctx_size);

    slot_ctx->route_string = 0;
    slot_ctx->ctx_entries = 1;
    slot_ctx->root_hub_port_number = usb_xhci_port_index(port);

    struct usb_xhci_endpoint_ctx *endpoint_ctx = usb_xhci_input_ctx_add_ctx(input_ctx, 1);
    if(endpoint_ctx == NULL) {
        usb_xhci_destroy_input_ctx(input_ctx);
        return -EINVAL;
    }
    memset(endpoint_ctx, 0, ctx_size);

    endpoint_ctx->endpoint_type = 4;
    endpoint_ctx->max_packet_size = 8;
    endpoint_ctx->max_burst_size = 0;
    endpoint_ctx->tr_dequeue_shifted_ptr =
        ((uintptr_t)usb_xhci_endpoint_get_transfer_ring_dequeue_pointer(default_endpoint)) >> 4;
    endpoint_ctx->dequeue_cycle_state = 1;
    endpoint_ctx->interval = 0;
    endpoint_ctx->max_primary_streams = 0;
    endpoint_ctx->mult = 0;
    endpoint_ctx->error_count = 3;

    uint8_t trb_type = USB_XHCI_TRB_TYPE_ADDR_DEVICE_CMD;
    uint8_t slot_type = 0x0;
    uint8_t slot_index = dev->slot_index;

    uint64_t param = (uintptr_t)usb_xhci_input_ctx_phys_addr(input_ctx);
    uint32_t status = 0x0;
    uint32_t control = ((uint32_t)trb_type << 10)
                     | ((uint32_t)slot_type << 16)
                     | ((uint32_t)slot_index << 24);
    res = usb_xhci_run_command(
            dev->xhci,
            &param,
            &status,
            &control);
    if(res) {
        wprintk("USB XHCI Failed to Run Address Device Command! (slotid=%d, portid=%d)\n",
                (int)dev->slot_index,
                (int)usb_xhci_port_index(port));
        return res;
    }

    uint8_t cc = (status >> 24) & 0xFF;
    if(!usb_xhci_trb_completion_code_is_success(cc)) {
        wprintk("USB XHCI Address Device Command Failed! (slotid=%d, portid=%d) (err=%s)\n",
                (int)dev->slot_index,
                (int)usb_xhci_port_index(port),
                usb_xhci_trb_completion_code_to_string(cc));
        return -EINVAL;
    }

    usb_xhci_destroy_input_ctx(input_ctx);

    return 0;
}

static struct usb_transfer *
usb_xhci_device_create_normal_transfer(
        struct usb_device *usb_dev,
        int dci,
        void __phys *buffer,
        size_t buflen)
{
    struct usb_xhci_device *dev = container_of(usb_dev, struct usb_xhci_device, usb_device);
    struct usb_xhci_endpoint *endp = dev->endpoints[dci];
    if(endp == NULL) {
        return NULL;
    }

    struct usb_xhci_transfer *xfer;
    xfer = usb_xhci_endpoint_create_normal_transfer(
            endp,
            buffer,
            buflen);
    if(xfer == NULL) {
        return NULL;
    }

    return &xfer->xfer;
}

static struct usb_transfer *
usb_xhci_device_create_setup_stage_transfer(
        struct usb_device *usb_dev,
        int dci,
        uint8_t bmRequestType,
        uint8_t bRequest,
        uint16_t wValue,
        uint16_t wIndex,
        uint16_t wLength,
        int trt)
{
    struct usb_xhci_device *dev = container_of(usb_dev, struct usb_xhci_device, usb_device);
    struct usb_xhci_endpoint *endp = dev->endpoints[dci];
    if(endp == NULL) {
        return NULL;
    }

    struct usb_xhci_transfer *xfer;
    xfer = usb_xhci_endpoint_create_setup_stage_transfer(
            endp,
            bmRequestType,
            bRequest,
            wValue,
            wIndex,
            wLength,
            trt);
    if(xfer == NULL) {
        return NULL;
    }

    return &xfer->xfer;
}

static struct usb_transfer *
usb_xhci_device_create_data_stage_transfer(
        struct usb_device *usb_dev,
        int dci,
        void __phys *buffer,
        size_t buflen,
        int dir)
{
    struct usb_xhci_device *dev = container_of(usb_dev, struct usb_xhci_device, usb_device);
    struct usb_xhci_endpoint *endp = dev->endpoints[dci];
    if(endp == NULL) {
        return NULL;
    }

    struct usb_xhci_transfer *xfer;
    xfer = usb_xhci_endpoint_create_data_stage_transfer(
            endp,
            buffer,
            buflen,
            dir);
    if(xfer == NULL) {
        return NULL;
    }

    return &xfer->xfer;
}

static struct usb_transfer *
usb_xhci_device_create_status_stage_transfer(
        struct usb_device *usb_dev,
        int dci,
        int dir)
{
    struct usb_xhci_device *dev = container_of(usb_dev, struct usb_xhci_device, usb_device);
    struct usb_xhci_endpoint *endp = dev->endpoints[dci];
    if(endp == NULL) {
        return NULL;
    }

    struct usb_xhci_transfer *xfer;
    xfer = usb_xhci_endpoint_create_status_stage_transfer(
            endp,
            dir);
    if(xfer == NULL) {
        return NULL;
    }

    return &xfer->xfer;
}

static struct usb_transfer *
usb_xhci_device_create_isoch_transfer(
        struct usb_device *usb_dev,
        int dci)
{
    struct usb_xhci_device *dev = container_of(usb_dev, struct usb_xhci_device, usb_device);
    struct usb_xhci_endpoint *endp = dev->endpoints[dci];
    if(endp == NULL) {
        return NULL;
    }

    struct usb_xhci_transfer *xfer;
    xfer = usb_xhci_endpoint_create_isoch_transfer(
            endp);
    if(xfer == NULL) {
        return NULL;
    }

    return &xfer->xfer;
}

static int
usb_xhci_device_destroy_transfer(
        struct usb_device *usb_dev,
        struct usb_transfer *gen_xfer)
{
    struct usb_xhci_device *dev = container_of(usb_dev, struct usb_xhci_device, usb_device);
    struct usb_xhci_transfer *xfer = container_of(gen_xfer, struct usb_xhci_transfer, xfer);
    return usb_xhci_destroy_transfer(xfer);
}

static struct usb_device_ops
usb_xhci_device_ops = {
    .create_normal_transfer = usb_xhci_device_create_normal_transfer,
    .create_setup_stage_transfer = usb_xhci_device_create_setup_stage_transfer,
    .create_data_stage_transfer = usb_xhci_device_create_data_stage_transfer,
    .create_status_stage_transfer = usb_xhci_device_create_status_stage_transfer,
    .create_isoch_transfer = usb_xhci_device_create_isoch_transfer,
    .destroy_transfer = usb_xhci_device_destroy_transfer,
};

int
usb_xhci_register_root_hub_device(
        struct usb_xhci_device *dev)
{
    int res;

    irq_lock_acquire(&dev->registry_lock);

    if(dev->registered) {
        irq_lock_release(&dev->registry_lock);
        return -EALREADY;
    }

    res = usb_host_register_device(
            &dev->usb_device,
            &usb_xhci_device_ops);
    if(res) {
        irq_lock_release(&dev->registry_lock);
        return res;
    } else {
        dev->registered = 1;
    }

    irq_lock_release(&dev->registry_lock);
    return 0;
}

int
usb_xhci_destroy_device(
        struct usb_xhci_device *dev)
{
    int res;

    if(dev->registered) {
        usb_host_deregister_device(&dev->usb_device);
        dev->registered = 0;
    }

    // Disable the slot

    // First mark the slot as "free" on the software side,
    // otherwise we have a possible race condition, where
    // we free the slot, another device is assigned to the slot,
    // and the we incorrectly clear the "devices" array.
    dev->xhci->devices[dev->slot_index-1] = NULL;

    mbarrier();

    for(size_t i = 0; i < 32; i++) {
        struct usb_xhci_endpoint *endp = dev->endpoints[i];
        if(endp != NULL) {
            res = usb_xhci_destroy_endpoint(endp);
            if(res) {
                wprintk("Failed to destroy USB endpoint on device destruction! (err=%s)\n",
                        errnostr(res));
            }
        }
    }

    res = usb_xhci_device_issue_disable_slot_command(dev);
    if(res) {
        wprintk("Failed to disable USB device slot on device destruction! (err=%s)\n",
                errnostr(res));
    }

    dma_free(dev->slot_dma_buffer, dev->ctx_size * 32);
    kfree(dev);
    return 0;
}

int
usb_xhci_device_notify_transfer_event(
        struct usb_xhci_device *dev,
        struct usb_xhci_trb *trb)
{
    int res;

    uint8_t endpoint = (trb->control >> 16) & 0x3F;

    irq_lock_acquire(&dev->endpoint_lock);

    struct usb_xhci_endpoint *endp = dev->endpoints[endpoint];
    if(endp == NULL) {
        irq_lock_release(&dev->endpoint_lock);
        return -ENXIO;
    }

    res = usb_xhci_endpoint_notify_transfer_event(endp, trb);
    if(res) {
        irq_lock_release(&dev->endpoint_lock);
        return res;
    }

    irq_lock_release(&dev->endpoint_lock);
    return 0;
}

