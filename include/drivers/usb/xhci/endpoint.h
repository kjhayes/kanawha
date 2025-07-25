#ifndef __KANAWHA__USB_XHCI_ENDPOINT_H__
#define __KANAWHA__USB_XHCI_ENDPOINT_H__

#include <kanawha/types.h>
#include <kanawha/lock.h>
#include <drivers/usb/xhci/ring.h>
#include <drivers/usb/xhci/device.h>


struct usb_xhci_endpoint
{
    struct usb_xhci_device *device;
    size_t dci;

    irq_lock_t lock;
    struct usb_xhci_trb_ring ring;
    ilist_t transfer_queue;
};

struct usb_xhci_endpoint *
usb_xhci_create_endpoint(
        struct usb_xhci_device *dev,
        size_t tr_size,
        size_t dci);

int
usb_xhci_destroy_endpoint(
        struct usb_xhci_endpoint *endp);

static inline void __phys *
usb_xhci_endpoint_get_transfer_ring_dequeue_pointer(
        struct usb_xhci_endpoint *endp)
{
    return endp->ring.dequeue_phys;
}

void
usb_xhci_endpoint_ring_doorbell(
        struct usb_xhci_endpoint *endp);

int
usb_xhci_endpoint_notify_transfer_event(
        struct usb_xhci_endpoint *endp,
        struct usb_xhci_trb *trb);

struct usb_xhci_transfer
{
    struct usb_transfer xfer;

    struct usb_xhci_endpoint *endpoint;
    ilist_node_t endpoint_queue_node;
    struct usb_xhci_trb *final_trb;

    union
    {
    struct {
        void __phys *buffer;
        size_t buflen;
    } normal;
    struct {
        uint8_t bmRequestType;
        uint8_t bRequest;
        uint16_t wValue;
        uint16_t wIndex;
        uint16_t wLength;
        int trt;
    } setup_stage;
    struct {
        void __phys *buffer;
        size_t buflen;
        int dir;
    } data_stage;
    struct {
        int dir;
    } status_stage;
    struct {
    } isoch;
    };
};

struct usb_xhci_transfer *
usb_xhci_endpoint_create_normal_transfer(
        struct usb_xhci_endpoint *endp,
        void __phys *buffer,
        size_t buflen);

struct usb_xhci_transfer *
usb_xhci_endpoint_create_setup_stage_transfer(
        struct usb_xhci_endpoint *endp,
        uint8_t bmRequestType,
        uint8_t bRequest,
        uint16_t wValue,
        uint16_t wIndex,
        uint16_t wLength,
        int trt);

struct usb_xhci_transfer *
usb_xhci_endpoint_create_data_stage_transfer(
        struct usb_xhci_endpoint *endp,
        void __phys *buffer,
        size_t buflen,
        int dir);

struct usb_xhci_transfer *
usb_xhci_endpoint_create_status_stage_transfer(
        struct usb_xhci_endpoint *endp,
        int dir);

struct usb_xhci_transfer *
usb_xhci_endpoint_create_isoch_transfer(
        struct usb_xhci_endpoint *endp);

int
usb_xhci_destroy_transfer(
        struct usb_xhci_transfer *xfer);

#endif
