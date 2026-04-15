#ifndef __KANAWHA__USB_XHCI_RING_H__
#define __KANAWHA__USB_XHCI_RING_H__

#include <drivers/usb/xhci/trb.h>
#include <kanawha/dma.h>
#include <kanawha/lock.h>
#include <kanawha/types.h>

struct usb_xhci;

struct usb_xhci_trb_ring
{
    size_t num_dma_regions;
    size_t region_size;
    size_t trbs_per_region; // Does not include the link TRB
    dma_addr_t *dma_regions;

    struct usb_xhci_trb __phys *dequeue_phys;
    size_t enqueue_region;
    size_t enqueue_index;
    unsigned pcs : 1;
};

int
usb_xhci_init_trb_ring(struct usb_xhci *xhci,
                       struct usb_xhci_trb_ring *ring,
                       size_t size);
int
usb_xhci_deinit_trb_ring(struct usb_xhci_trb_ring *ring);

int
usb_xhci_trb_ring_get_avail_trbs(struct usb_xhci_trb_ring *ring,
                                 struct usb_xhci_trb **trbbuf,
                                 struct usb_xhci_trb __phys **sentinel,
                                 size_t buflen);

int
usb_xhci_trb_ring_advance_enqueued(struct usb_xhci_trb_ring *ring,
                                   size_t amount);

#endif
