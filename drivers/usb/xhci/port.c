
#include <drivers/usb/xhci/port.h>
#include <drivers/usb/xhci/xhci.h>
#include <drivers/usb/xhci/reg.h>

static inline size_t
usb_xhci_port_index(
        struct usb_xhci_port *port)
{
    return ((void*)port - (void*)&port->xhci->ports[0])/sizeof(*port);
}

static uint32_t
usb_xhci_port_read_portsc(
        struct usb_xhci_port *port)
{
    le32_t le = pci_bar_readl(
            &port->xhci->func->bars[0],
            port->register_offset + 0x0);
    return letoh32(le);
}
static void
usb_xhci_port_write_portsc(
        struct usb_xhci_port *port,
        uint32_t value)
{
    le32_t le = htole32(value);
    pci_bar_writel(
            &port->xhci->func->bars[0],
            port->register_offset + 0x0,
            value);
}

static int
usb_xhci_port_is_powered(
        struct usb_xhci_port *port)
{
    return (usb_xhci_port_read_portsc(port) >> 9) & 0b1;
}

static int
usb_xhci_port_assert_powered(
        struct usb_xhci_port *port)
{
    int have_ctrl = usb_xhci_cap_reg_get_port_power_control(port->xhci);
    if(!have_ctrl) {
        return 0;
    }

    uint32_t portsc = usb_xhci_port_read_portsc(port);
    if(!((portsc>>9) & 0b1)) {
        portsc |= (1ULL<<9);
        usb_xhci_port_write_portsc(port, portsc);
        // XHCI Spec requires delaying for 20ms after asserting the port is powered.
        clk_delay(msec_to_duration(20));

        portsc = usb_xhci_port_read_portsc(port);
        if(!((portsc>>9) & 0b1)) {
            // Failed to power on the port
            return -EINVAL;
        }
    }

    return 0;

}

static int
usb_xhci_reset_port(
        struct usb_xhci_port *port)
{
    int res;
    res = usb_xhci_port_assert_powered(port);
    if(res) {
        return res;
    }

    uint32_t portsc = usb_xhci_port_read_portsc(port);
    portsc |= (1ULL<<4);
    usb_xhci_port_write_portsc(port, portsc);
    return 0;
}

int
usb_xhci_init_ports(
        struct usb_xhci *xhci)
{
    int res;

    xhci->num_ports = usb_xhci_cap_reg_get_max_ports(xhci);
    xhci->ports = kmalloc(sizeof(struct usb_xhci_port) * xhci->num_ports);
    if(xhci->ports == NULL) {
        return -ENOMEM;
    }
    memset(xhci->ports, 0, sizeof(struct usb_xhci_port) * xhci->num_ports);

    for(size_t i = 0; i < xhci->num_ports; i++) {
        xhci->ports[i].xhci = xhci;
        xhci->ports[i].register_offset = xhci->op_reg_offset + 0x400 + (0x10 * i);
    }

    return 0;
}

int
usb_xhci_deinit_ports(
        struct usb_xhci *xhci)
{
    kfree(xhci->ports);
    return 0;
}

int
usb_xhci_reset_all_ports(
        struct usb_xhci *dev)
{
    int res;
    int num_failed = 0;
    for(size_t i = 0; i < dev->num_ports; i++) {
        struct usb_xhci_port *port = &dev->ports[i];
        res = usb_xhci_reset_port(port);
        if(res) {
            wprintk("Failed to reset USB XHCI port! (err=%s)\n",
                    errnostr(res));
            num_failed++;
        }
    }
    if(num_failed > 0) {
        return -EINVAL;
    }
    return 0;
}

static int
usb_xhci_port_on_attach(
        struct usb_xhci_port *port,
        uint32_t portsc)
{
    printk("Device Attached to USB Port %lu\n",
            (ul_t)usb_xhci_port_index(port));
    return -EUNIMPL;
}

static int
usb_xhci_port_on_deattach(
        struct usb_xhci_port *port,
        uint32_t portsc)
{
    printk("Device Deattached from USB Port %lu\n",
            (ul_t)usb_xhci_port_index(port));
    return -EUNIMPL;
}

int
usb_xhci_port_notify_status_change(
        struct usb_xhci_port *port)
{
    // TODO: This should be put in a tasklet of some sort.
    uint32_t portsc = usb_xhci_port_read_portsc(port);

    usb_xhci_port_write_portsc(port, portsc); // Clear all changed events

    if((portsc >> 17) & 0b1) {
        int connected = (portsc >> 0) & 0b1;
        if(connected) {
            usb_xhci_port_on_attach(port, portsc);
        } else {
            usb_xhci_port_on_deattach(port, portsc);
        }
    }

    return 0;
}

int
usb_xhci_dump_ports(
        struct usb_xhci *dev,
        printk_f *printer)
{
    for(size_t i = 0; i < dev->num_ports; i++) {
        uint32_t portsc = usb_xhci_port_read_portsc(&dev->ports[i]);
        unsigned link_state = (portsc >> 5) & 0xF;
        unsigned speed = (portsc >> 10) & 0xF;
        unsigned indicator = (portsc >> 14) & 0x3;
        (*printer)("PORT[%lu] {\n"
                   "\tConnected=%s\n"
                   "\tEnabled=%s\n"
                   "\tPowered=%s\n"
                   "\tOver-Current=%s\n"
                   "\tLink-State=%s\n"
                   "\tSpeed=%u\n"
                   "\tIndicator=%s\n"
                   "}\n",
                (ul_t)i,
                portsc & (1ULL<<0) ? "YES" : "NO",
                portsc & (1ULL<<1) ? "YES" : "NO",
                portsc & (1ULL<<9) ? "YES" : "NO",
                portsc & (1ULL<<3) ? "YES" : "NO",
                link_state == 0 ?  "U0 (Normal Operational)" :
                link_state == 1 ?  "U1 (Receive/Transmit Circuitry Quiesced)" :
                link_state == 2 ?  "U2 (Clock Possibly Quiesced)" :
                link_state == 3 ?  "U3 (Suspend)" :
                link_state == 4 ?  "Disabled" :
                link_state == 5 ?  "RxDetect" :
                link_state == 6 ?  "Inactive" :
                link_state == 7 ?  "Polling" :
                link_state == 8 ?  "Recovery" :
                link_state == 9 ?  "Hot-Reset" :
                link_state == 10 ? "Compliance-Mode" :
                link_state == 11 ? "Test-Mode" :
                link_state == 15 ? "Resume" :
                                   "UNKNOWN",
                speed,
                indicator == 0 ? "OFF" :
                indicator == 1 ? "AMBER" :
                indicator == 2 ? "GREEN" :
                                 "UNKNOWN"
                );
    }
    return 0;
}

