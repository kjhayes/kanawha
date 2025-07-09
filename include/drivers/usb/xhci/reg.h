#ifndef __KANAWHA__USB_XHCI_REG_H__
#define __KANAWHA__USB_XHCI_REG_H__

#include <drivers/usb/xhci/xhci.h>

#define USB_XHCI_PCI_CLASS    (0x0C)
#define USB_XHCI_PCI_SUBCLASS (0x03)
#define USB_XHCI_PCI_PROG_IF  (0x30)

#define USB_XHCI_CAP_CAP_LENGTH         0x00
#define USB_XHCI_CAP_INTERFACE_VERSION  0x02
#define USB_XHCI_CAP_STRUCT_PARAM_1     0x04
#define USB_XHCI_CAP_STRUCT_PARAM_2     0x08
#define USB_XHCI_CAP_STRUCT_PARAM_3     0x0C
#define USB_XHCI_CAP_CAP_PARAM_1        0x10
#define USB_XHCI_CAP_DOORBELL_OFFSET    0x14
#define USB_XHCI_CAP_RUNTIME_REG_OFFSET 0x18
#define USB_XHCI_CAP_CAP_PARAM_2        0x1C

#define USB_XHCI_OP_USB_COMMAND                 0x00
#define USB_XHCI_OP_USB_STATUS                  0x04
#define USB_XHCI_OP_PAGE_SIZE                   0x08
#define USB_XHCI_OP_DEV_NOTIF_CTRL              0x14
#define USB_XHCI_OP_CMD_RING_CTRL               0x18
#define USB_XHCI_OP_DEV_CTX_BASE_ADDR_ARRAY_PTR 0x30
#define USB_XHCI_OP_CONFIGURE                   0x38

static inline uint32_t
usb_xhci_read_usb_status_reg(
        struct usb_xhci *xhci)
{
    le32_t le = pci_bar_readl(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_USB_STATUS);
    return letoh32(le);
}

static inline uint32_t
usb_xhci_read_usb_command_reg(
        struct usb_xhci *xhci)
{
    le32_t le = pci_bar_readl(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_USB_COMMAND);
    return letoh32(le);
}

static inline size_t
usb_xhci_cap_reg_get_cap_length(
        struct usb_xhci *xhci)
{
    return pci_bar_readb(&xhci->func->bars[0], USB_XHCI_CAP_CAP_LENGTH);
}
static inline size_t
usb_xhci_cap_reg_get_hci_version(
        struct usb_xhci *xhci)
{
    return pci_bar_readw(&xhci->func->bars[0], USB_XHCI_CAP_CAP_LENGTH);
}
static inline size_t
usb_xhci_cap_reg_get_max_device_slots(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_STRUCT_PARAM_1);
    return p & 0xFF;
}
static inline size_t
usb_xhci_cap_reg_get_max_interruptors(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_STRUCT_PARAM_1);
    return (p >> 8) & 0x3FF;
}
static inline size_t
usb_xhci_cap_reg_get_max_ports(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_STRUCT_PARAM_1);
    return (p >> 24) & 0xFF;
}
static inline size_t
usb_xhci_cap_reg_get_isochronous_scheduling_threshold(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_STRUCT_PARAM_2);
    return p & 0xF;
}
static inline order_t
usb_xhci_cap_reg_get_event_ring_segment_table_max(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_STRUCT_PARAM_2);
    return (p>>4) & 0xF;
}
static inline size_t
usb_xhci_cap_reg_get_num_scratchpads(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_STRUCT_PARAM_2);
    uint32_t high = ((p >> 21) & 0x1F);
    uint32_t low = ((p >> 27) & 0x1F);
    return (high<<5) | low;
}
static inline size_t
usb_xhci_cap_reg_get_scratchpad_restore(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_STRUCT_PARAM_2);
    return (p >> 26) & 0b1;
}

static inline size_t
usb_xhci_cap_reg_get_64bit_capable(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_CAP_PARAM_1);
    return p & 0b1;
}
static inline size_t
usb_xhci_cap_reg_get_bandwidth_negotiable(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_CAP_PARAM_1);
    return (p >> 1) & 0b1;
}
static inline size_t
usb_xhci_cap_reg_get_64_byte_context_structs(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_CAP_PARAM_1);
    return (p >> 2) & 0b1;
}
static inline size_t
usb_xhci_cap_reg_get_port_power_control(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_CAP_PARAM_1);
    return (p >> 3) & 0b1;
}
static inline size_t
usb_xhci_cap_reg_get_port_indicators(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_CAP_PARAM_1);
    return (p >> 4) & 0b1;
}

static inline size_t
usb_xhci_cap_reg_get_doorbell_offset(
        struct usb_xhci *xhci)
{
    return pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_DOORBELL_OFFSET);
}
static inline size_t
usb_xhci_cap_reg_get_runtime_reg_offset(
        struct usb_xhci *xhci)
{
    return pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_RUNTIME_REG_OFFSET);
}
static inline size_t
usb_xhci_cap_reg_get_ext_cap_ptr(
        struct usb_xhci *xhci)
{
    uint32_t p = pci_bar_readl(&xhci->func->bars[0], USB_XHCI_CAP_CAP_PARAM_1);
    return (p >> 16) & 0xFFFF;
}

static inline int
usb_xhci_usb_command_set_bit(
        struct usb_xhci *xhci,
        int value,
        int bit)
{
    uint32_t cmd = pci_bar_readl(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_USB_COMMAND);
    cmd &= ~(1ULL<<bit);
    cmd |= ((uint32_t)!!value)<<bit;
    pci_bar_writel(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_USB_COMMAND,
            cmd);
    return 0;
}

static inline int
usb_xhci_usb_command_get_bit(
        struct usb_xhci *xhci,
        int bit)
{
    uint32_t cmd = pci_bar_readl(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_USB_COMMAND);
    return (cmd >> bit) & 0b1;
}

#define usb_xhci_command_reg_set_run_stop(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 0))
#define usb_xhci_command_reg_get_run_stop(xhci) (usb_xhci_usb_command_get_bit((xhci), 0))
#define usb_xhci_command_reg_set_host_controller_reset(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 1))
#define usb_xhci_command_reg_get_host_controller_reset(xhci) (usb_xhci_usb_command_get_bit((xhci), 1))
#define usb_xhci_command_reg_set_interruptor_enable(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 2))
#define usb_xhci_command_reg_get_interruptor_enable(xhci) (usb_xhci_usb_command_get_bit((xhci), 2))
#define usb_xhci_command_reg_set_host_system_error_enable(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 3))
#define usb_xhci_command_reg_get_host_system_error_enable(xhci) (usb_xhci_usb_command_get_bit((xhci), 3))
#define usb_xhci_command_reg_set_light_host_controller_reset(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 7))
#define usb_xhci_command_reg_get_light_host_controller_reset(xhci) (usb_xhci_usb_command_get_bit((xhci), 7))
#define usb_xhci_command_reg_set_controller_save_state(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 8))
#define usb_xhci_command_reg_get_controller_save_state(xhci) (usb_xhci_usb_command_get_bit((xhci), 8))
#define usb_xhci_command_reg_set_controller_restore_state(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 9))
#define usb_xhci_command_reg_get_controller_restore_state(xhci) (usb_xhci_usb_command_get_bit((xhci), 9))
#define usb_xhci_command_reg_set_event_wrap_enable(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 10))
#define usb_xhci_command_reg_get_event_wrap_enable(xhci) (usb_xhci_usb_command_get_bit((xhci), 10))
#define usb_xhci_command_reg_set_u3_mfindex_stop(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 11))
#define usb_xhci_command_reg_get_u3_mfindex_stop(xhci) (usb_xhci_usb_command_get_bit((xhci), 11))
#define usb_xhci_command_reg_set_cem_enable(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 13))
#define usb_xhci_command_reg_get_cem_enable(xhci) (usb_xhci_usb_command_get_bit((xhci), 13))
#define usb_xhci_command_reg_set_ext_tbc_enable(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 14))
#define usb_xhci_command_reg_get_ext_tbc_enable(xhci) (usb_xhci_usb_command_get_bit((xhci), 14))
#define usb_xhci_command_reg_set_ext_tbc_trb_status_enable(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 15))
#define usb_xhci_command_reg_get_ext_tbc_trb_status_enable(xhci) (usb_xhci_usb_command_get_bit((xhci), 15))
#define usb_xhci_command_reg_set_vtio_enable(xhci, value) (usb_xhci_usb_command_set_bit((xhci), (value), 16))
#define usb_xhci_command_reg_get_vtio_enable(xhci) (usb_xhci_usb_command_get_bit((xhci), 16))

static inline int
usb_xhci_usb_status_set_bit(
        struct usb_xhci *xhci,
        int value,
        int bit)
{
    uint32_t cmd = pci_bar_readl(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_USB_COMMAND);
    cmd &= ~(1ULL<<bit);
    cmd |= ((uint32_t)!!value)<<bit;
    pci_bar_writel(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_USB_COMMAND, cmd);
    return 0;
}

static inline int
usb_xhci_usb_status_get_bit(
        struct usb_xhci *xhci,
        int bit)
{
    uint32_t cmd = pci_bar_readl(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_USB_STATUS);
    return (cmd >> bit) & 0b1;
}

#define usb_xhci_status_reg_get_host_controller_halted(xhci) (usb_xhci_usb_status_get_bit((xhci), 0))
#define usb_xhci_status_reg_get_host_system_error(xhci) (usb_xhci_usb_status_get_bit((xhci), 2))
#define usb_xhci_status_reg_clear_host_system_error(xhci) (usb_xhci_usb_status_set_bit((xhci), 1, 2))
#define usb_xhci_status_reg_get_event_interrupt(xhci) (usb_xhci_usb_status_get_bit((xhci), 3))
#define usb_xhci_status_reg_clear_event_interrupt(xhci) (usb_xhci_usb_status_get_bit((xhci), 1, 3))
#define usb_xhci_status_reg_get_port_change_detect(xhci) (usb_xhci_usb_status_get_bit((xhci), 4))
#define usb_xhci_status_reg_clear_port_change_detect(xhci) (usb_xhci_usb_status_set_bit((xhci), 1, 4))
#define usb_xhci_status_reg_get_save_state_status(xhci) (usb_xhci_usb_status_get_bit((xhci), 8))
#define usb_xhci_status_reg_get_restore_state_status(xhci) (usb_xhci_usb_status_get_bit((xhci), 9))
#define usb_xhci_status_reg_get_save_restore_error(xhci) (usb_xhci_usb_status_get_bit((xhci), 10))
#define usb_xhci_status_reg_clear_save_restore_error(xhci) (usb_xhci_usb_status_set_bit((xhci), 1, 10))
#define usb_xhci_status_reg_get_controller_not_ready(xhci) (usb_xhci_usb_status_get_bit((xhci), 11))
#define usb_xhci_status_reg_get_host_controller_error(xhci) (usb_xhci_usb_status_get_bit((xhci), 12))

static inline order_t
usb_xhci_op_reg_get_page_order(
        struct usb_xhci *xhci)
{
    uint32_t val = pci_bar_readl(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_PAGE_SIZE);
    return val + 12;
}
static inline int
usb_xhci_op_reg_set_device_ctx_base_address_array_pointer(
        struct usb_xhci *xhci,
        void __phys *ptr)
{
    if((uintptr_t)ptr & 0x3F) {
        return -EINVAL;
    }

    pci_bar_writeq(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_DEV_CTX_BASE_ADDR_ARRAY_PTR,
            (uintptr_t)ptr);

    return 0;
}

static inline int
usb_xhci_command_ring_running(
        struct usb_xhci *xhci)
{
    le32_t value = pci_bar_readl(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_CMD_RING_CTRL);
    return (letoh32(value) & (1ULL<<3)); // This masking shouldn't be necessary (all bits but CRR should be "read-as-zero")
}

static inline int
usb_xhci_set_command_ring_pointer(
        struct usb_xhci *xhci,
        void __phys *command_ring,
        int consumer_cycle)
{
    if((uintptr_t)command_ring & 0x3F) {
        return -EINVAL;
    }

    le64_t raw = pci_bar_readq(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_CMD_RING_CTRL);

    uint64_t value = letoh64(raw);

    if(value & (1ULL<<3)) {
        // The command ring is currently running!
        return -EBUSY;
    }

    value = (uintptr_t)command_ring;
    value |= !!(consumer_cycle); // Set the cycle bit

    uint32_t high = (value >> 32);
    uint32_t low = (value & 0xFFFFFFFFULL);

    dprintk("set_command_ring_pointer(%p, low=0x%lx, high=0x%lx)\n",
            value,
            low,
            high);

    pci_bar_writel(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_CMD_RING_CTRL,
            htole32(low));
    pci_bar_writel(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_CMD_RING_CTRL + 4,
            htole32(high));

    return 0;
}

static inline int
usb_xhci_set_max_device_slots_enabled(
        struct usb_xhci *xhci,
        size_t no_devices)
{
    uint64_t value = pci_bar_readq(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_CONFIGURE);

    DEBUG_ASSERT(no_devices <= 0xFF);

    value &= ~(0xFF); // This shouldn't be necessary but let's be cautious of weird hardware
    value |= (no_devices & 0xFF);

    pci_bar_writeq(
            &xhci->func->bars[0],
            xhci->op_reg_offset + USB_XHCI_OP_CONFIGURE,
            value);

    return 0;
}

#endif
