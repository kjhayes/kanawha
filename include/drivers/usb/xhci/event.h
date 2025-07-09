#ifndef __KANAWHA__USB_XHCI_EVENT_H__
#define __KANAWHA__USB_XHCI_EVENT_H__

#include <kanawha/dma.h>
#include <drivers/usb/xhci/trb.h>
#include <kanawha/irq.h>
#include <kanawha/lock.h>

struct usb_xhci;

struct usb_xhci_interruptor
{
    struct usb_xhci *xhci;
    size_t index;

    irq_lock_t lock;

    irq_t irq;
    struct irq_action *action;

    size_t num_segments;
    size_t segment_size;
    size_t trbs_per_segment;
    dma_addr_t *segments;
    dma_addr_t segment_table;

    size_t dequeue_segment;
    size_t dequeue_index;
    unsigned ccs : 1;

    size_t register_offset;
};

int
usb_xhci_init_interruptors(
        struct usb_xhci *dev);
int
usb_xhci_deinit_interruptors(
        struct usb_xhci *dev);

// Called by the interrupt handler when
// a new event appears.
//
// (Can be used to "poke" the interruptor to check for
//  new events in case we miss an interrupt somehow)
int
usb_xhci_interruptor_event_queue_notify(
        struct usb_xhci_interruptor *intr);

#endif
