
#include <kanawha/types.h>
#include <kanawha/dma.h>
#include <drivers/usb/xhci/trb.h>
#include <drivers/usb/xhci/ring.h>
#include <drivers/usb/xhci/xhci.h>

int
usb_xhci_init_trb_ring(
        struct usb_xhci *xhci,
        struct usb_xhci_trb_ring *ring,
        size_t size)
{
    int res;

    // Determine how many pages we will need
    // (Subtracting one per page for the link TRB)
    size_t page_size = 1ULL<<xhci->page_order; 
    size_t trbs_per_page = (page_size / 16) - 1;
    size_t pages_needed = (size / trbs_per_page) + !!(size % trbs_per_page);

    ring->num_dma_regions = pages_needed;
    ring->region_size = page_size;
    ring->trbs_per_region = trbs_per_page;
    ring->dma_regions = kmalloc(sizeof(dma_addr_t) * ring->num_dma_regions, KM_KERNEL);
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

    ring->dequeue_phys = dma_phys_addr(ring->dma_regions[0]);

    return 0;
}

int
usb_xhci_deinit_trb_ring(
        struct usb_xhci_trb_ring *ring)
{
    for(size_t i = 0; i < ring->num_dma_regions; i++) {
        dma_free(ring->dma_regions[i], ring->region_size);
    }
    kfree(ring->dma_regions);
    return 0;
}

int
usb_xhci_trb_ring_get_avail_trbs(
        struct usb_xhci_trb_ring *ring,
        struct usb_xhci_trb **trbbuf,
        size_t buflen)
{
    if(buflen == 0) {
        return 0;
    }

    if(buflen > 1) {
        return -EUNIMPL;
    }

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
        return -ENOMEM;
    }

    struct usb_xhci_trb *region = dma_virt_addr(ring->dma_regions[ring->enqueue_region]); 
    struct usb_xhci_trb *trb = &region[ring->enqueue_index];

    trbbuf[0] = trb;

    return 0;
}

int
usb_xhci_trb_ring_advance_enqueued(
        struct usb_xhci_trb_ring *ring,
        size_t amount)
{
    for(size_t i = 0; i < amount; i++)
    {
        struct usb_xhci_trb *cur_region =
            dma_virt_addr(ring->dma_regions[ring->enqueue_region]);

        struct usb_xhci_trb *cur_trb =
            &cur_region[ring->enqueue_index];

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
    }

    return 0;
}

