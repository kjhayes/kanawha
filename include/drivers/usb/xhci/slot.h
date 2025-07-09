#ifndef __KANAWHA__USB_XHCI_SLOT_H__
#define __KANAWHA__USB_XHCI_SLOT_H__

#include <stdint.h>
#include <kanawha/assert.h>
#include <kanawha/pointer.h>

struct usb_xhci_slot_ctx {
    uint32_t route_string : 20;
    uint32_t speed : 4;
    uint32_t __rsvd_0 : 1;
    uint32_t multi_tt : 1;
    uint32_t hub : 1;
    uint32_t ctx_entries : 5;
    uint16_t max_exit_latency;
    uint8_t root_hub_port_number;
    uint8_t number_of_ports;
    uint8_t parent_hub_slot_id;
    uint8_t parent_port_number;
    uint32_t tt_think_time : 2;
    uint32_t __rsvd_1 : 4;
    uint32_t interruptor_target : 10;
    uint8_t usb_device_address;
    uint32_t __rsvd_2 : 19;
    uint32_t slot_state : 5;
    uint32_t __rsvd_3;
    uint32_t __rsvd_4;
    uint32_t __rsvd_5;
    uint32_t __rsvd_6;
} __attribute__((packed));
ASSERT_TYPE_SIZE(struct usb_xhci_slot_ctx, 0x20);

struct usb_xhci_endpoint_ctx {
    uint32_t endpoint_state : 3;
    uint32_t __rsvd_0 : 5;
    uint32_t mult : 2;
    uint32_t max_primary_streams : 5;
    uint32_t linear_stream_array : 1;
    uint8_t interval;
    uint8_t max_esit_payload_hi;
    uint32_t __rsvd_1 : 1;
    uint32_t error_count : 2;
    uint32_t endpoint_type : 3;
    uint32_t __rsvd_2 : 1;
    uint32_t host_initiate_disable : 1;
    uint8_t max_burst_size;
    uint16_t max_packet_size;
    uint32_t dequeue_cycle_state : 1;
    uint32_t __rsvd_3 : 3;
    uint64_t tr_dequeue_shifted_ptr: 60;
    uint16_t avg_trb_length;
    uint16_t max_esit_payload_lo;
    uint32_t __rsvd_4;
    uint32_t __rsvd_5;
    uint32_t __rsvd_6;
} __attribute__((packed));
ASSERT_FIELD_OFFSET(struct usb_xhci_endpoint_ctx, interval, 0x2);
ASSERT_FIELD_OFFSET(struct usb_xhci_endpoint_ctx, max_packet_size, 0x6);
ASSERT_FIELD_OFFSET(struct usb_xhci_endpoint_ctx, avg_trb_length, 0x10);
ASSERT_FIELD_OFFSET(struct usb_xhci_endpoint_ctx, max_esit_payload_lo, 0x12);
ASSERT_TYPE_SIZE(struct usb_xhci_endpoint_ctx, 0x20);

struct usb_xhci_device_ctx {
    struct usb_xhci_slot_ctx slot_ctx;
    struct usb_xhci_endpoint_ctx ep_ctxs[31];
} __attribute__((packed));
ASSERT_TYPE_SIZE(struct usb_xhci_device_ctx, 0x400);

struct usb_xhci_dcbaa
{
    void __phys *scratchpad_array_ptr;
    void __phys *device_ctx_base_address[];
} __attribute__((packed));
ASSERT_FIELD_OFFSET(struct usb_xhci_dcbaa, device_ctx_base_address, 8);

#endif
