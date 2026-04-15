
#include <drivers/pci/irq.h>
#include <drivers/usb/xhci/command.h>
#include <drivers/usb/xhci/device.h>
#include <drivers/usb/xhci/event.h>
#include <drivers/usb/xhci/port.h>
#include <drivers/usb/xhci/reg.h>
#include <drivers/usb/xhci/xhci.h>
#include <kanawha/dma.h>
#include <kanawha/kmalloc.h>
#include <kanawha/types.h>

// Register Access

// Unneeded for now, but having the code here is useful
// (Note: This means it is NOT TESTED!)
// static int
// usb_xhci_interruptor_enabled(
//        struct usb_xhci_interruptor *intr)
//{
//    uint32_t iman = pci_bar_readl(
//            &intr->xhci->func->bars[0],
//            intr->register_offset + 0x0);
//    return iman & (1ULL<<1);
//}

static int
usb_xhci_enable_interruptor(struct usb_xhci_interruptor *intr)
{
    uint32_t iman =
        pci_bar_readl(&intr->xhci->func->bars[0], intr->register_offset + 0x0);
    iman |= (1ULL << 1);
    iman &= ~(1ULL << 0); // Do not write the pending bit (which would clear it)
    pci_bar_writel(&intr->xhci->func->bars[0],
                   intr->register_offset + 0x0,
                   iman);
    return 0;
}
static int
usb_xhci_disable_interruptor(struct usb_xhci_interruptor *intr)
{
    uint32_t iman =
        pci_bar_readl(&intr->xhci->func->bars[0], intr->register_offset + 0x0);
    iman &= ~(1ULL << 1);
    iman &= ~(1ULL << 0); // Do not write the pending bit (which would clear it)
    pci_bar_writel(&intr->xhci->func->bars[0],
                   intr->register_offset + 0x0,
                   iman);
    return 0;
}

// Useful but unused functions currently (Untested)
// static int
// usb_xhci_interruptor_pending(
//        struct usb_xhci_interruptor *intr)
//{
//    uint32_t iman = pci_bar_readl(
//            &intr->xhci->func->bars[0],
//            intr->register_offset + 0x0);
//    return iman & (1ULL<<0);
//}
// static int
// usb_xhci_clear_pending_interruptor(
//        struct usb_xhci_interruptor *intr)
//{
//    uint32_t iman = pci_bar_readl(
//            &intr->xhci->func->bars[0],
//            intr->register_offset + 0x0);
//    iman |= (1ULL<<0);
//    pci_bar_writel(
//            &intr->xhci->func->bars[0],
//            intr->register_offset + 0x0,
//            iman);
//    return 0;
//}

static int
usb_xhci_interruptor_set_segment_table_pointer(
    struct usb_xhci_interruptor *intr,
    void __phys *ptr)
{
    // Set the segment table pointer
    pci_bar_writeq(&intr->xhci->func->bars[0],
                   intr->register_offset + 0x10,
                   htole64((uint64_t)ptr));
    return 0;
}
static int
usb_xhci_interruptor_set_segment_table_size(struct usb_xhci_interruptor *intr,
                                            uint16_t entries)
{
    pci_bar_writel(&intr->xhci->func->bars[0],
                   intr->register_offset + 0x8,
                   htole32((uint16_t)intr->num_segments));
    return 0;
}
static int
usb_xhci_interruptor_set_dequeue_pointer(struct usb_xhci_interruptor *intr,
                                         void __phys *ptr,
                                         size_t segment_index,
                                         int clear_busy)
{
    // Set the ring dequeue_pointer
    DEBUG_ASSERT(((uint64_t)ptr & 0xF) == 0);

    uint64_t value = (uint64_t)ptr;

    value |= segment_index & 0b111;

    // EHB bit should be zero (bit 3) (clear it to be explicit)
    value &= ~(1ULL << 3);
    value |= ((!!clear_busy) << 3);

    pci_bar_writeq(&intr->xhci->func->bars[0],
                   intr->register_offset + 0x18,
                   htole64(value));
    return 0;
}

#define USB_XHCI_EVT_RING_ENTRIES 256

static inline int
usb_xhci_dispatch_port_status_change(struct usb_xhci *dev,
                                     struct usb_xhci_trb *trb)
{
    uint8_t cc = (trb->status >> 24) & 0xFF;

    if(!usb_xhci_trb_completion_code_is_success(cc))
    {
        return -EINVAL;
    }

    uint8_t port_id = (letoh64(trb->param) >> 24) & 0xFF;

    // USB XHCI spec indexes ports from 1 but this driver indexes from 0
    // (this is a dumb inconsistency but I'll leave it alone for now)
    port_id -= 1;

    if(port_id >= dev->num_ports)
    {
        return -EINVAL;
    }

    struct usb_xhci_port *port = &dev->ports[port_id];

    return usb_xhci_port_notify_status_change(port);
}

static inline int
usb_xhci_dispatch_command_completion(struct usb_xhci *dev,
                                     struct usb_xhci_trb *trb)
{
    return usb_xhci_notify_command_completion(dev, trb);
}

static inline int
usb_xhci_dispatch_transfer_event(struct usb_xhci *xhci,
                                 struct usb_xhci_trb *trb)
{
    int res;

    uint8_t slot_id = (trb->control >> 24) & 0xFF;

    irq_lock_acquire(&xhci->devices_lock);

    struct usb_xhci_device *dev = xhci->devices[slot_id - 1];
    if(dev == NULL)
    {
        irq_lock_release(&xhci->devices_lock);
        wprintk("USB XHCI received transfer event for missing device (slotid=%ld)!\n",
                (sl_t)slot_id);
        return -ENXIO;
    }

    res = usb_xhci_device_notify_transfer_event(dev, trb);
    if(res)
    {
        irq_lock_release(&xhci->devices_lock);
        return res;
    }

    irq_lock_release(&xhci->devices_lock);
    return 0;
}

static inline int
usb_xhci_dispatch_event(struct usb_xhci_interruptor *intr,
                        struct usb_xhci_trb *trb)
{
    uint32_t status = letoh32(trb->status);
    uint32_t control = letoh32(trb->control);

    uint8_t cc = (status >> 24) & 0xFF;
    uint8_t type = (control >> 10) & 0x3F;

    switch(type)
    {
    case USB_XHCI_TRB_TYPE_PORT_STATUS_CHANGE_EVENT:
        return usb_xhci_dispatch_port_status_change(intr->xhci, trb);
    case USB_XHCI_TRB_TYPE_COMMAND_COMPLETION_EVENT:
        return usb_xhci_dispatch_command_completion(intr->xhci, trb);
    case USB_XHCI_TRB_TYPE_TRANSFER_EVENT:
        return usb_xhci_dispatch_transfer_event(intr->xhci, trb);
    case USB_XHCI_TRB_TYPE_BANDWIDTH_REQUEST_EVENT:
    case USB_XHCI_TRB_TYPE_DOORBELL_EVENT:
    case USB_XHCI_TRB_TYPE_HOST_CONTROLLER_EVENT:
    case USB_XHCI_TRB_TYPE_DEVICE_NOTIFICATION_EVENT:
    case USB_XHCI_TRB_TYPE_MFINDEX_WRAP_EVENT:
        wprintk("Received USB Event of Unimplemented Type %s (code=%s) "
                "(Ignoring...)\n",
                usb_xhci_trb_type_to_string(type),
                usb_xhci_trb_completion_code_to_string(cc));
        return -EUNIMPL;
    default:
        wprintk("Received USB Event TRB of Invalid Type %s (code=%s)!\n",
                usb_xhci_trb_type_to_string(type),
                usb_xhci_trb_completion_code_to_string(cc));
        return -EINVAL;
    }
}

int
usb_xhci_interruptor_event_queue_notify(struct usb_xhci_interruptor *intr)
{
    irq_lock_acquire(&intr->lock);

    int dequeued_a_trb;
    int cur_dequeued_a_trb;

    dprintk("usb_xhci_interruptor_event_queue_notify (index=%lu)\n",
            (ul_t)intr->index);

    do
    {
        cur_dequeued_a_trb = 0;

        struct usb_xhci_trb *cur_segment =
            dma_virt_addr(intr->segments[intr->dequeue_segment]);
        struct usb_xhci_trb *cur_trb = &cur_segment[intr->dequeue_index];
        int cycle = usb_xhci_trb_get_cycle(cur_trb);
        if(!cycle == !intr->ccs)
        {
            dequeued_a_trb = 1;
            cur_dequeued_a_trb = 1;
            // Handle the TRB

            usb_xhci_dispatch_event(intr, cur_trb);

            intr->dequeue_index++;
            if(intr->dequeue_index >= intr->trbs_per_segment)
            {
                intr->dequeue_index = 0;
                intr->dequeue_segment++;
                if(intr->dequeue_segment >= intr->num_segments)
                {
                    dprintk("USB XHCI Event Queue Flipping "
                            "CCS Bit...\n");
                    intr->ccs ^= 1;
                    intr->dequeue_segment = 0;
                }
            }
        }
        else
        {
            dprintk("Not dequeue-ing cycle=%d, ccs=%d\n",
                    (int)cycle,
                    (int)intr->ccs);
        }
    } while(cur_dequeued_a_trb);

    if(dequeued_a_trb)
    {
        size_t index = intr->dequeue_index;
        size_t segment = intr->dequeue_segment;
        struct usb_xhci_trb __phys *phys_seg =
            dma_phys_addr(intr->segments[segment]);
        struct usb_xhci_trb __phys *phys_trb = &phys_seg[index];
        usb_xhci_interruptor_set_dequeue_pointer(intr,
                                                 (void __phys *)phys_trb,
                                                 segment,
                                                 1);
    }
    else
    {
        if(usb_xhci_read(intr->xhci, HCE))
        {
            eprintk("Failed to dequeue event from USB XHCI event queue "
                    "and an "
                    "error has been asserted by the host controller!\n");
        }
    }

    irq_lock_release(&intr->lock);
    return 0;
}

static int
usb_xhci_interruptor_irq_handler(struct excp_state *excp_state,
                                 struct irq_action *action)
{
    int res;

    struct usb_xhci_interruptor *intr = action->handler_data.priv_data;

    res = usb_xhci_interruptor_event_queue_notify(intr);
    if(res)
    {
        wprintk("Error occurred when servicing USB XHCI interrupt! (err=%s)\n",
                errnostr(res));
    }

    return IRQ_NONE;
}

struct __packed usb_xhci_erst_entry
{
    le64_t segment_phys;
    le16_t segment_size;
    uint16_t __rsvd_0;
    uint32_t __rsvd_1;
};
ASSERT_TYPE_SIZE(struct usb_xhci_erst_entry, 16);

static int
usb_xhci_init_interruptor(struct usb_xhci *dev, size_t index)
{
    int res;

    struct usb_xhci_interruptor *intr = &dev->interruptors[index];
    intr->xhci = dev;
    intr->index = index;
    intr->register_offset =
        (intr->xhci->runtime_reg_offset + 0x20) + (32 * index);
    irq_lock_init(&intr->lock);

    // Double check that the interruptor is disabled
    usb_xhci_disable_interruptor(intr);

    intr->irq = pci_func_get_irq(dev->func, index);

    struct irq_desc *desc = irq_to_desc(intr->irq);
    intr->action =
        irq_install_handler(desc, intr, usb_xhci_interruptor_irq_handler);
    if(intr->action == NULL)
    {
        return -EINVAL;
    }

    order_t page_order = dev->page_order;
    size_t page_size = 1ULL << page_order;
    if(page_size < 64)
    {
        // Need to be greater than cache line sized/aligned
        irq_uninstall_action(intr->action);
        return -EINVAL;
    }
    size_t entries_per_page = page_size / sizeof(struct usb_xhci_trb);
    size_t pages_needed = USB_XHCI_EVT_RING_ENTRIES / entries_per_page +
                          !!(USB_XHCI_EVT_RING_ENTRIES % entries_per_page);

    // Check ERST Max
    order_t erst_max_order = usb_xhci_read(dev, ERST_Max);
    if(pages_needed > 1ULL << erst_max_order)
    {
        irq_uninstall_action(intr->action);
        return -EINVAL;
    }

    intr->num_segments = pages_needed;
    intr->segment_size = page_size;
    intr->trbs_per_segment = entries_per_page;

    if(intr->trbs_per_segment > 1ULL << 16)
    {
        // Too large pages? (We could recover from this but for now assume
        // this won't happen)
        irq_uninstall_action(intr->action);
        return -EINVAL;
    }

    intr->segments =
        kmalloc(sizeof(dma_addr_t) * intr->num_segments, KM_KERNEL);
    if(intr->segments == NULL)
    {
        irq_uninstall_action(intr->action);
        wprintk("Failed to allocate segment pointers for USB XHCI interruptor "
                "event ring! (num_segments=%ld)\n",
                (sl_t)intr->num_segments);
        return -ENOMEM;
    }

    res = dma_alloc(sizeof(struct usb_xhci_erst_entry) * intr->num_segments,
                    6,
                    dev->is_64bit ? DMA_PHYS_64 : DMA_PHYS_32,
                    &intr->segment_table);
    if(res)
    {
        irq_uninstall_action(intr->action);
        kfree(intr->segments);
        return res;
    }

    // Clear the ERST
    void *erst_ptr = dma_virt_addr(intr->segment_table);
    memset(erst_ptr,
           0,
           sizeof(struct usb_xhci_erst_entry) * intr->num_segments);

    struct usb_xhci_erst_entry *erst = erst_ptr;

    for(size_t i = 0; i < intr->num_segments; i++)
    {
        res = dma_alloc(intr->segment_size,
                        page_order,
                        dev->is_64bit ? DMA_PHYS_64 : DMA_PHYS_32,
                        &intr->segments[i]);
        if(res)
        {
            for(size_t undo_i = 0; undo_i < i; undo_i++)
            {
                dma_free(intr->segments[undo_i], intr->segment_size);
            }
            irq_uninstall_action(intr->action);
            kfree(intr->segments);
            return res;
        }
        void *segment_data = dma_virt_addr(intr->segments[i]);
        memset(segment_data, 0, page_size);
        erst[i].segment_phys =
            htole64((uint64_t)dma_phys_addr(intr->segments[i]));
        erst[i].segment_size = htole16((uint16_t)intr->trbs_per_segment);
    }

    intr->dequeue_segment = 0;
    intr->dequeue_index = 0;
    intr->ccs = 1;

    usb_xhci_interruptor_set_dequeue_pointer(intr,
                                             dma_phys_addr(intr->segments[0]),
                                             intr->dequeue_segment,
                                             1);
    usb_xhci_interruptor_set_segment_table_size(intr, intr->num_segments);
    usb_xhci_interruptor_set_segment_table_pointer(
        intr,
        dma_phys_addr(intr->segment_table));

    res = usb_xhci_enable_interruptor(intr);
    if(res)
    {
        for(size_t i = 0; i < intr->num_segments; i++)
        {
            dma_free(intr->segments[i], intr->segment_size);
        }
        kfree(intr->segments);
        dma_free(intr->segment_table,
                 sizeof(struct usb_xhci_erst_entry) * intr->num_segments);
        irq_uninstall_action(intr->action);
        return res;
    }

    unmask_irq(intr->irq);

    return 0;
}

static int
usb_xhci_deinit_interruptor(struct usb_xhci *dev, size_t index)
{
    struct usb_xhci_interruptor *intr = &dev->interruptors[index];
    mask_irq(intr->irq);
    usb_xhci_disable_interruptor(intr);
    usb_xhci_interruptor_set_segment_table_pointer(intr, (void __phys *)0x0);
    usb_xhci_interruptor_set_dequeue_pointer(intr, (void __phys *)0x0, 0x0, 0);
    usb_xhci_interruptor_set_segment_table_size(intr, 0);
    for(size_t i = 0; i < intr->num_segments; i++)
    {
        dma_free(intr->segments[i], intr->segment_size);
    }
    kfree(intr->segments);
    dma_free(intr->segment_table,
             sizeof(struct usb_xhci_erst_entry) * intr->num_segments);
    irq_uninstall_action(intr->action);
    return 0;
}

int
usb_xhci_init_interruptors(struct usb_xhci *dev)
{
    int res;

    size_t max_intr = usb_xhci_read(dev, MaxIntrs);

    res = pci_func_start_irqs(dev->func);
    if(res)
    {
        wprintk("USB XHCI Device failed to start IRQ(s)!\n");
        return res;
    }

    size_t num_irqs = pci_func_num_irqs(dev->func);

    if(num_irqs < 1)
    {
        wprintk("USB XHCI Device has too few interrupts available!\n");
        pci_func_stop_irqs(dev->func);
        return -EINVAL;
    }

    size_t num_intr = max_intr;
    if(num_intr > num_irqs)
    {
        num_intr = num_irqs;
    }

    dev->num_interruptors = num_intr;
    dev->interruptors =
        kzmalloc(sizeof(struct usb_xhci_interruptor) * dev->num_interruptors,
                 KM_KERNEL);
    if(dev->interruptors == NULL)
    {
        pci_func_stop_irqs(dev->func);
        wprintk("Failed to allocate interruptors for USB XHCI! "
                "(num_interruptors=%ld)\n",
                (sl_t)dev->num_interruptors);
        return -ENOMEM;
    }

    // Set up every interruptor's IRQ handler
    for(size_t i = 0; i < dev->num_interruptors; i++)
    {
        res = usb_xhci_init_interruptor(dev, i);
        if(res)
        {
            for(size_t undo_i = 0; undo_i < i; undo_i++)
            {
                usb_xhci_deinit_interruptor(dev, undo_i);
            }
            dev->num_interruptors = 0;
            kfree(dev->interruptors);
            pci_func_stop_irqs(dev->func);
            return res;
        }
    }

    usb_xhci_write(dev, INTE, 1);

    return 0;
}

int
usb_xhci_deinit_interruptors(struct usb_xhci *dev)
{
    usb_xhci_write(dev, INTE, 0);
    for(size_t i = 0; i < dev->num_interruptors; i++)
    {
        usb_xhci_deinit_interruptor(dev, i);
    }
    dev->num_interruptors = 0;
    kfree(dev->interruptors);
    pci_func_stop_irqs(dev->func);
    return 0;
}
