#ifndef __KANAWHA__XHCI_H__
#define __KANAWHA__XHCI_H__

#include <drivers/pci/bar.h>
#include <drivers/pci/pci.h>
#include <drivers/usb/xhci/command.h>
#include <drivers/usb/xhci/event.h>
#include <drivers/usb/xhci/port.h>
#include <kanawha/dma.h>
#include <kanawha/types.h>

struct usb_xhci_device;

struct usb_xhci
{
    struct pci_func *func;

    // Register Offsets
    size_t doorbell_offset;
    size_t runtime_reg_offset;
    size_t op_reg_offset;
    size_t port_reg_offset;

    // Basic Cached Info
    order_t page_order;
    size_t num_device_ctx;
    size_t num_scratchpads;
    int is_64bit;

    // scratchpad buffers
    dma_addr_t scratchpad_array;
    void __phys **scratchpad_pages;

    // device contextes state
    dma_addr_t dcbaa_dma;
    struct usb_xhci_dcbaa *dcbaa;
    irq_lock_t devices_lock;
    struct usb_xhci_device **devices;

    // command ring state
    struct usb_xhci_command_ring command_ring;

    // interruptors state
    size_t num_interruptors;
    struct usb_xhci_interruptor *interruptors;

    // ports state
    size_t num_ports;
    struct usb_xhci_port *ports;
};

#endif
