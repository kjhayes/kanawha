
#include <stdint.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/mbarrier.h>
#include <drivers/usb/xhci/xhci.h>
#include <drivers/usb/xhci/command.h>
#include <drivers/usb/xhci/reg.h>
#include <drivers/usb/xhci/trb.h>
#include <drivers/pci/bar.h>

static int
usb_xhci_command_ring_ring_doorbell(
        struct usb_xhci_command_ring *ring)
{
    pci_bar_writel(
        &ring->xhci->func->bars[0],
        ring->xhci->doorbell_offset + 0x0,
        0x0);
    return 0;
}

int
usb_xhci_init_command_ring(
        struct usb_xhci *xhci,
        size_t size)
{
    int res;

    struct usb_xhci_command_ring *ring = &xhci->command_ring;

    if(usb_xhci_command_ring_running(xhci)) {
        wprintk("usb_xhci_init_command_ring called while the command ring was running!\n");
        return -EBUSY;
    }

    ring->xhci = xhci;
    irq_lock_init(&ring->lock);
    ilist_init(&ring->command_queue);

    // Determine how many pages we will need
    // (Subtracting one per page for the link TRB)
    size_t page_size = 1ULL<<xhci->page_order; 
    size_t trbs_per_page = (page_size / 16) - 1;
    size_t pages_needed = (size / trbs_per_page) + !!(size % trbs_per_page);

    ring->num_dma_regions = pages_needed;
    ring->region_size = page_size;
    ring->trbs_per_region = trbs_per_page;
    ring->dma_regions = kmalloc(sizeof(dma_addr_t) * ring->num_dma_regions);
    if(ring->dma_regions == NULL) {
        return -ENOMEM;
    }

    // Allocate the dma regions
    for(size_t i = 0; i < ring->num_dma_regions; i++)
    {
        res = dma_alloc(
                page_size,
                xhci->page_order,
                xhci->is_64bit ? DMA_PHYS_64 : DMA_PHYS_32,
                &ring->dma_regions[i]);
        if(res) {
            for(size_t undo_i = 0; undo_i < i; undo_i++) {
                dma_free(ring->dma_regions[undo_i], page_size);
            }
            kfree(ring->dma_regions);
            return res;
        }
    }

    // Clear the dma regions
    for(size_t i = 0; i < ring->num_dma_regions; i++) {
        void *page = dma_virt_addr(ring->dma_regions[i]);
        memset(page, 0, page_size);
    }

    // Create links between regions (except the wrapping link)
    for(size_t i = 1; i < ring->num_dma_regions; i++)
    {
        struct usb_xhci_trb *from_trbs = dma_virt_addr(ring->dma_regions[i-1]);
        void __phys *to_addr = dma_phys_addr(ring->dma_regions[i]);

        struct usb_xhci_trb *link_trb = &from_trbs[trbs_per_page];
        link_trb->param = htole64((uintptr_t)to_addr);
        link_trb->status = 0;
        link_trb->control = 0;
        usb_xhci_trb_set_type(link_trb, USB_XHCI_TRB_TYPE_LINK);
    }

    // Create the cycle link
    void __phys *start_addr = dma_phys_addr(ring->dma_regions[0]);
    {
        struct usb_xhci_trb *final_trbs = dma_virt_addr(ring->dma_regions[ring->num_dma_regions-1]);
        struct usb_xhci_trb *link_trb = &final_trbs[trbs_per_page];
        link_trb->param = htole64((uintptr_t)start_addr);
        link_trb->status = 0;
        link_trb->control = 0;
        link_trb->control |= htole32(1ULL<<1); // Toggle the meaning of the cycle bit when we cross this boundary
        usb_xhci_trb_set_type(link_trb, USB_XHCI_TRB_TYPE_LINK);
    }

    ring->enqueue_region = 0;
    ring->enqueue_index = 0;
    ring->pcs = 1;

    ring->dequeue_phys = start_addr;
    dprintk("RING_DEQUEUE_START=%p\n",
            start_addr);

    res = usb_xhci_set_command_ring_pointer(
            xhci,
            start_addr,
            1);
    if(res) {
        for(size_t i = 0; i < ring->num_dma_regions; i++) {
            dma_free(ring->dma_regions[i], ring->region_size);
        }
        kfree(ring->dma_regions);
        return res;
    }

    return 0;
}

int
usb_xhci_start_command_ring(
        struct usb_xhci *xhci)
{
    int res;

    struct usb_xhci_command_ring *ring = &xhci->command_ring;

    res = usb_xhci_command_ring_ring_doorbell(ring);
    if(res) {
        return res;
    }

    // Don't wait for it to "start" if we haven't enqueued a command
//    duration_t delay = msec_to_duration(2);
//    duration_t max_wait = sec_to_duration(2);
//    duration_t amt_waited = 0;
//    while(!usb_xhci_command_ring_running(xhci)) {
//        clk_delay(delay);
//        amt_waited += delay;
//        if(amt_waited >= max_wait) {
//            eprintk("Failed to start USB command ring within %d second(s)!\n"
//                    "\tUSBCMD=0x%lx\n"
//                    "\tUSBSTS=0x%lx\n"
//                    ,
//                    (int)duration_to_sec(max_wait),
//                    (ul_t)usb_xhci_read_usb_command_reg(xhci),
//                    (ul_t)usb_xhci_read_usb_status_reg(xhci)
//                    );
//            return -ETIMEDOUT;
//        }
//    }

    return 0;
}

int
usb_xhci_deinit_command_ring(
        struct usb_xhci *xhci)
{
    struct usb_xhci_command_ring *ring = &xhci->command_ring;

    for(size_t i = 0; i < ring->num_dma_regions; i++) {
        dma_free(ring->dma_regions[i], ring->region_size);
    }
    kfree(ring->dma_regions);
    return 0;
}

struct usb_xhci_command
{
    struct usb_xhci_command_ring *ring;
    ilist_node_t list_node;

    unsigned complete : 1;
    uint64_t completion_param;
    uint32_t completion_status;
    uint32_t completion_control;
};

int
usb_xhci_notify_command_completion(
        struct usb_xhci *xhci,
        struct usb_xhci_trb *cc_trb)
{
    // TODO: This might be worth putting in a tasklet of some sort.
    struct usb_xhci_command_ring *ring = &xhci->command_ring;

    irq_lock_acquire(&ring->lock);
    ilist_node_t *node = ilist_pop_head(&ring->command_queue);
    if(node == NULL) {
        wprintk("usb_xhci_notify_command_completion called without an outstanding command!\n");
        return -EINVAL;
    }
    struct usb_xhci_command *cmd =
        container_of(node, struct usb_xhci_command, list_node);

    cmd->completion_param = letoh64(cc_trb->param);
    cmd->completion_status = letoh32(cc_trb->status);
    cmd->completion_control = letoh32(cc_trb->control);
    mbarrier();
    cmd->complete = 1;

    irq_lock_release(&ring->lock);
    return 0;
}

static struct usb_xhci_trb *
usb_xhci_command_ring_get_avail_trb_lockless(
        struct usb_xhci_command_ring *ring
        )
{
    int full = 0;
    if(ring->enqueue_index == ring->trbs_per_region-1) {
        size_t next_region;
        if(ring->enqueue_region == ring->num_dma_regions-1) {
            next_region = 0;
        } else {
            next_region = ring->enqueue_region+1;
        }
        struct usb_xhci_trb __phys *phys_region =
            dma_phys_addr(ring->dma_regions[next_region]);

        struct usb_xhci_trb __phys *next_trb = &phys_region[0];

        full = (ring->dequeue_phys == next_trb);
    }
    else {
        struct usb_xhci_trb __phys *phys_region =
            dma_phys_addr(ring->dma_regions[ring->enqueue_region]);
        full = (ring->dequeue_phys == &phys_region[ring->enqueue_index+1]);
    }

    if(full) {
        return NULL;
    }

    struct usb_xhci_trb *region = dma_virt_addr(ring->dma_regions[ring->enqueue_region]); 
    struct usb_xhci_trb *trb = &region[ring->enqueue_index];

    return trb;
}

static int
usb_xhci_command_ring_advance_enqueue_lockless(
        struct usb_xhci_command_ring *ring)
{
    struct usb_xhci_trb *cur_region = dma_virt_addr(ring->dma_regions[ring->enqueue_region]);
    struct usb_xhci_trb *cur_trb = &cur_region[ring->enqueue_index];

    uint32_t control = letoh32(cur_trb->control);
    control &= ~0b1;
    control |= !!ring->pcs;
    cur_trb->control = control;
    if(ring->enqueue_index == ring->trbs_per_region-1) {
        struct usb_xhci_trb *link = cur_trb + 1;
        uint32_t link_control = letoh32(link->control);
        link_control &= ~0b1;
        link_control |= !!ring->pcs;
        link->control = link_control;
        if(link_control & 0b10) {
            ring->pcs = ~ring->pcs;
        }
    }

    ring->enqueue_index++;
    if(ring->enqueue_index >= ring->trbs_per_region) {
        ring->enqueue_index = 0;
        ring->enqueue_region++;
        if(ring->enqueue_region >= ring->num_dma_regions) {
            ring->enqueue_region = 0;
        }
    }

    return 0;
}

static int
usb_xhci_launch_command(
        struct usb_xhci *xhci,
        struct usb_xhci_command *cmd,
        uint64_t param,
        uint32_t status,
        uint32_t control)
{
    struct usb_xhci_command_ring *ring = &xhci->command_ring;
    irq_lock_acquire(&ring->lock);

    cmd->ring = ring;

    struct usb_xhci_trb *next_trb =
        usb_xhci_command_ring_get_avail_trb_lockless(ring);

    if(next_trb == NULL) {
        irq_lock_release(&ring->lock);
        return -EBUSY; // Command queue is full
    }

    cmd->complete = 0;
    ilist_push_tail(&ring->command_queue, &cmd->list_node);

    dprintk("xhci launch command (cmd=%p, status=0x%lx, control=0x%lx)\n",
            param,
            status,
            control);

    next_trb->param = htole64(param);
    next_trb->status = htole32(status);
    // Must preserve the cycle bit
    next_trb->control = htole32((control & ~0b1) | (letoh32(next_trb->control) & 0b1));

    usb_xhci_command_ring_advance_enqueue_lockless(ring);

    irq_lock_release(&ring->lock);

    usb_xhci_command_ring_ring_doorbell(ring);

    return 0;
}

static int
usb_xhci_await_command(
        struct usb_xhci_command *cmd
        )
{
    while(!((volatile struct usb_xhci_command*)cmd)->complete) {
        // Should sit on a waitqueue with timeout...
        clk_delay(msec_to_duration(1));
        if(!irqs_enabled()) {
            usb_xhci_interruptor_event_queue_notify(
                    &cmd->ring->xhci->interruptors[0]);
        }
    }
    return 0;
}

int
usb_xhci_run_command(
        struct usb_xhci *xhci,
        uint64_t *param,
        uint32_t *status,
        uint32_t *control)
{
    int res;

    struct usb_xhci_command cmd;

    DEBUG_ASSERT(KERNEL_ADDR(param));
    uint64_t param_value = *param;
    DEBUG_ASSERT(KERNEL_ADDR(status));
    uint32_t status_value = *status;
    DEBUG_ASSERT(KERNEL_ADDR(control));
    uint32_t control_value = *control;

    dprintk("Launched command\n");
    res = usb_xhci_launch_command(
            xhci,
            &cmd,
            param_value,
            status_value,
            control_value);
    if(res) {
        return res;
    }

    dprintk("Awaiting command\n");
    res = usb_xhci_await_command(
            &cmd);
    if(res) {
        return res;
    }

    *param = cmd.completion_param;
    *status = cmd.completion_status;
    *control = cmd.completion_control;

    return 0;
}

int
usb_xhci_run_noop_command(
        struct usb_xhci *xhci)
{
    int res;

    uint64_t param = 0x0;
    uint32_t status = 0x0;
    uint32_t control = (uint32_t)(((uint32_t)USB_XHCI_TRB_TYPE_NOOP_CMD & 0x3F) << 10);
    res = usb_xhci_run_command(
            xhci,
            &param,
            &status,
            &control
            );
    if(res) {
        return res;
    }

    uint8_t cc = (status >> 24) & 0xFF;

    if(!usb_xhci_trb_completion_code_is_success(cc)) {
        wprintk("usb_xhci NOOP command returned non-success completion code %s\n",
                usb_xhci_trb_completion_code_to_string(cc));
        return -EINVAL;
    }

    return 0;
}

int
usb_xhci_dump_command_ring(
        printk_f *printer,
        struct usb_xhci *xhci)
{
    struct usb_xhci_command_ring *ring = &xhci->command_ring;
    for(size_t i = 0; i < ring->num_dma_regions; i++) {
        (*printer)("Command Ring Region[%lu] {\n", (ul_t)i);
        struct usb_xhci_trb *region = dma_virt_addr(ring->dma_regions[i]);
        for(size_t j = 0; j <= ring->trbs_per_region; j++) { // <= for the link TRB
            struct usb_xhci_trb *trb = &region[j];
            usb_xhci_dump_trb(printer, trb);
            (*printer)("\n");
        }
        (*printer)("}\n");
    }
    return 0;
}

