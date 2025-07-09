#ifndef __KANAWHA__USB_XHCI_COMMAND_H__
#define __KANAWHA__USB_XHCI_COMMAND_H__

#include <stdint.h>
#include <kanawha/dma.h>
#include <kanawha/endian.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>

struct usb_xhci;
struct usb_xhci_trb;

struct usb_xhci_command_ring
{
    struct usb_xhci *xhci;

    size_t num_dma_regions;
    size_t region_size;
    size_t trbs_per_region; // Does not include the link TRB
    dma_addr_t *dma_regions;

    irq_lock_t lock;

    struct usb_xhci_trb __phys *dequeue_phys;
    size_t enqueue_region;
    size_t enqueue_index;
    unsigned pcs : 1;
    ilist_t command_queue;
};

int
usb_xhci_init_command_ring(
        struct usb_xhci *xhci,
        size_t size);
int
usb_xhci_start_command_ring(
        struct usb_xhci *xhci);
int
usb_xhci_deinit_command_ring(
        struct usb_xhci *xhci);

// Called by zero-th interruptor when a completion
// event is dequeued from the event ring
int
usb_xhci_notify_command_completion(
        struct usb_xhci *xhci,
        struct usb_xhci_trb *cc_trb);

int
usb_xhci_run_command(
        struct usb_xhci *xhci,
        uint64_t *param,
        uint32_t *status,
        uint32_t *control);

int
usb_xhci_run_noop_command(
        struct usb_xhci *xhci);

int
usb_xhci_dump_command_ring(
        printk_f *printer,
        struct usb_xhci *xhci);

#endif
