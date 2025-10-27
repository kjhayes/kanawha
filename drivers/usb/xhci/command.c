
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
    usb_xhci_write_doorbell(
            ring->xhci,
            0, 0, 0);

    return 0;
}

int
usb_xhci_init_command_ring(
        struct usb_xhci *xhci,
        size_t size)
{
    int res;

    struct usb_xhci_command_ring *ring = &xhci->command_ring;

    if(usb_xhci_read(xhci, CRR)) {
        wprintk("usb_xhci_init_command_ring called while the command ring was running!\n");
        return -EBUSY;
    }

    ring->xhci = xhci;
    irq_lock_init(&ring->lock);
    ilist_init(&ring->command_queue);

    res = usb_xhci_init_trb_ring(
            xhci,
            &ring->ring,
            size);
    if(res) {
	wprintk("usb_xhci_init_command_ring: Failed to initialize TRB ring!\n");
	return res;
    }

    uint64_t crcr = (uint64_t)ring->ring.dequeue_phys | 0b1;

    usb_xhci_write(xhci, CRCR, crcr);

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

    return 0;
}

int
usb_xhci_deinit_command_ring(
        struct usb_xhci *xhci)
{
    struct usb_xhci_command_ring *ring = &xhci->command_ring;

    usb_xhci_deinit_trb_ring(&ring->ring);
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



static int
usb_xhci_launch_command(
        struct usb_xhci *xhci,
        struct usb_xhci_command *cmd,
        uint64_t param,
        uint32_t status,
        uint32_t control)
{
    int res;

    struct usb_xhci_command_ring *ring = &xhci->command_ring;
    irq_lock_acquire(&ring->lock);

    cmd->ring = ring;

    struct usb_xhci_trb *next_trb = NULL;

    res = usb_xhci_trb_ring_get_avail_trbs(&ring->ring, &next_trb, 1);
    if(res) {
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

    usb_xhci_trb_ring_advance_enqueued(&ring->ring, 1);

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

    printk("usb_xhci_run_command: launched command\n");
    res = usb_xhci_launch_command(
            xhci,
            &cmd,
            param_value,
            status_value,
            control_value);
    if(res) {
        return res;
    }

    printk("usb_xhci_run_command: awaiting command\n");
    res = usb_xhci_await_command(
            &cmd);
    if(res) {
        return res;
    }

    *param = cmd.completion_param;
    *status = cmd.completion_status;
    *control = cmd.completion_control;

    printk("usb_xhci_run_command: completed command\n");
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
    struct usb_xhci_command_ring *cmd_ring = &xhci->command_ring;
    struct usb_xhci_trb_ring *ring = &cmd_ring->ring;

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

