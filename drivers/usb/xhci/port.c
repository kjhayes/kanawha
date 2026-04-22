
#include <drivers/usb/xhci/cap.h>
#include <drivers/usb/xhci/device.h>
#include <drivers/usb/xhci/port.h>
#include <drivers/usb/xhci/reg.h>
#include <drivers/usb/xhci/xhci.h>
#include <kanawha/tasklet.h>

// Forward Decl
static void
usb_xhci_port_handle_status_change(void *state);

// Definitions
size_t
usb_xhci_port_index(struct usb_xhci_port *port)
{
    return (((void *)port - (void *)&port->xhci->ports[0]) / sizeof(*port)) + 1;
}

static uint32_t
usb_xhci_port_read_portsc(struct usb_xhci_port *port)
{
    le32_t le =
        pci_bar_readl(&port->xhci->func->bars[0], port->register_offset + 0x0);
    return letoh32(le);
}
static void
usb_xhci_port_write_portsc(struct usb_xhci_port *port, uint32_t value)
{
    le32_t le = htole32(value);
    pci_bar_writel(&port->xhci->func->bars[0],
                   port->register_offset + 0x0,
                   value);
}

uint8_t
usb_xhci_port_speed(struct usb_xhci_port *port)
{
    uint32_t portsc = usb_xhci_port_read_portsc(port);
    return (portsc >> 10) & 0xF;
}

// Useful but uneeded function (Untested)
// static int
// usb_xhci_port_is_powered(
//        struct usb_xhci_port *port)
//{
//    return (usb_xhci_port_read_portsc(port) >> 9) & 0b1;
//}

static int
usb_xhci_port_assert_powered(struct usb_xhci_port *port)
{
    int have_ctrl = usb_xhci_read(port->xhci, PPC);
    if(!have_ctrl)
    {
        return 0;
    }

    uint32_t portsc = usb_xhci_port_read_portsc(port);

    portsc &= ~(1UL << 1); // Do not set the Enabled/Disabled bit
    portsc &= ~(1UL << 4); // Do not set the Port reset bit
    portsc &= ~(0xF << 5); // Clear the PLS field
    portsc |= (1UL << 5);  // Set PLS to 1 (ignored by device)

    if(!((portsc >> 9) & 0b1))
    {
        portsc |= (1ULL << 9);
        usb_xhci_port_write_portsc(port, portsc);
        // XHCI Spec requires delaying for 20ms after asserting the port is
        // powered.
        clk_delay(msec_to_duration(20));

        portsc = usb_xhci_port_read_portsc(port);
        if(!((portsc >> 9) & 0b1))
        {
            // Failed to power on the port
            return -EINVAL;
        }
    }

    return 0;
}

static int
usb_xhci_reset_port(struct usb_xhci_port *port)
{
    int res;
    res = usb_xhci_port_assert_powered(port);
    if(res)
    {
        return res;
    }

    uint32_t portsc = usb_xhci_port_read_portsc(port);
    portsc |= (1ULL << 4);
    usb_xhci_port_write_portsc(port, portsc);

    // Wait for 100ms
    clk_delay(msec_to_duration(100));
    portsc = usb_xhci_port_read_portsc(port);
    if(portsc & (1UL << 1))
    {
        return 0;
    }
    else
    {
        if(port->version_major == 3)
        {
            // USB 3 devices require a PLS write
            // to re-enable after reset
            return 0;
        }
        return -ENODEV;
    }
}

static int
usb_xhci_enable_port(struct usb_xhci_port *port)
{
    int res;
    res = usb_xhci_port_assert_powered(port);
    if(res)
    {
        return res;
    }

    if(port->version_major == 2 || port->version_major == 1)
    {
        printk("XHCI: Resetting port %d to enable USB2 port\n",
               (int)usb_xhci_port_index(port));
        return usb_xhci_reset_port(port);
    }
    else if(port->version_major == 3)
    {
        uint32_t portsc = usb_xhci_port_read_portsc(port);

        portsc &= ~(1UL << 1);   // Do not set the Enabled/Disabled bit
        portsc &= ~(1UL << 4);   // Do not set the Port reset bit
        portsc &= ~(0xF << 5);   // Clear the PLS field
        portsc |= (1UL << 5);    // Set PLS to 5 (Disabled -> RxDetect)
        portsc |= (1UL << 16);   // Allow writes to PLS
        portsc &= ~(0x3F << 17); // Do not clear any status flags

        usb_xhci_port_write_portsc(port, portsc);
        return 0;
    }
    else
    {
        return -EINVAL;
    }
}

static void
usb_xhci_supported_protocol_cap_callback(struct usb_xhci *xhci,
                                         size_t cap_offset,
                                         void *priv_state)
{
    uint32_t version_data = pci_bar_readl(&xhci->func->bars[0], cap_offset);

    uint8_t minor = (version_data >> 16) & 0xFF;
    uint8_t major = (version_data >> 24) & 0xFF;

    uint32_t namestring = pci_bar_readl(&xhci->func->bars[0], cap_offset + 4);
    uint32_t data = pci_bar_readl(&xhci->func->bars[0], cap_offset + 8);
    uint8_t port_offset = data & 0xFF;
    uint8_t port_count = (data >> 8) & 0xFF;
    uint16_t protocol_defined = (data >> 16) & 0xFFF;
    uint8_t psic = (data >> 28) & 0xF;

    printk("XHCI: supported protocol capability \"%c%c%c%c\" (USB %d.%d) "
           "(ports=[%d-%d])\n",
           ((char *)&namestring)[0],
           ((char *)&namestring)[1],
           ((char *)&namestring)[2],
           ((char *)&namestring)[3],
           (int)major,
           (int)minor,
           (int)port_offset,
           (int)(port_offset + (port_count - 1)));

    for(size_t i = port_offset; i < port_offset + port_count; i++)
    {
        if(i > xhci->num_ports)
        {
            wprintk("XHCI: Found invalid port number %d in supported protocols "
                    "capability!\n",
                    i);
            continue;
        }
        struct usb_xhci_port *port = &xhci->ports[i - 1];
        port->version_major = major;
        port->version_minor = minor;
    }
}

int
usb_xhci_init_ports(struct usb_xhci *xhci)
{
    int res;

    xhci->num_ports = usb_xhci_read(xhci, MaxPorts);
    xhci->ports =
        kzmalloc(sizeof(struct usb_xhci_port) * xhci->num_ports, KM_KERNEL);
    if(xhci->ports == NULL)
    {
        return -ENOMEM;
    }

    for(size_t i = 0; i < xhci->num_ports; i++)
    {
        xhci->ports[i].xhci = xhci;
        xhci->ports[i].register_offset =
            xhci->op_reg_offset + 0x400 + (0x10 * i);
        xhci->ports[i].status = USB_XHCI_PORT_STATUS_UNKNOWN;
        xhci->ports[i].version_major = 0;
        xhci->ports[i].version_minor = 0;
        xhci->ports[i].status_change_tasklet = NULL;
    }

    usb_xhci_for_each_capability_of_type(
        xhci,
        USB_XHCI_EXT_CAPABILITY_ID_SUPPORTED_PROTOCOLS,
        usb_xhci_supported_protocol_cap_callback,
        NULL);

    for(size_t i = 0; i < xhci->num_ports; i++)
    {
        xhci->ports[i].status_change_tasklet =
            tasklet_create(usb_xhci_port_handle_status_change, &xhci->ports[i]);
        if(xhci->ports[i].status_change_tasklet == NULL)
        {
            for(size_t undo_i = 0; undo_i < i; undo_i++)
            {
                tasklet_destroy(xhci->ports[undo_i].status_change_tasklet);
            }
            kfree(xhci->ports);
            return -EINVAL;
        }
        tasklet_name(xhci->ports[i].status_change_tasklet,
                     "xhci-status-change");
    }

    return 0;
}

int
usb_xhci_deinit_ports(struct usb_xhci *xhci)
{
    for(size_t i = 0; i < xhci->num_ports; i++)
    {
        tasklet_destroy(xhci->ports[i].status_change_tasklet);
    }
    kfree(xhci->ports);
    return 0;
}

int
usb_xhci_reset_all_ports(struct usb_xhci *dev)
{
    int res;
    int num_failed = 0;
    for(size_t i = 0; i < dev->num_ports; i++)
    {
        struct usb_xhci_port *port = &dev->ports[i];
        res = usb_xhci_reset_port(port);
        if(res)
        {
            wprintk("Failed to reset USB XHCI port! (err=%s)\n", errnostr(res));
            num_failed++;
        }
    }
    if(num_failed > 0)
    {
        return -EINVAL;
    }
    return 0;
}

static int
usb_xhci_port_on_attach(struct usb_xhci_port *port, uint32_t portsc)
{
    int res;

    printk("Device Attached to USB Port %lu\n",
           (ul_t)usb_xhci_port_index(port));

    struct usb_xhci_device *dev = usb_xhci_create_device(port->xhci);
    if(dev == NULL)
    {
        eprintk("usb_xhci_port_on_attach: failed to create device!\n");
        return -EINVAL;
    }

    printk("Addressing USB Device...\n");
    res = usb_xhci_address_root_hub_device(dev, port);
    if(res)
    {
        eprintk("usb_xhci_port_on_attach: Failed to address root hub USB "
                "device!\n");
        usb_xhci_destroy_device(dev);
        return res;
    }

    printk("Registering USB Device...\n");
    res = usb_xhci_register_root_hub_device(dev);
    if(res)
    {
        wprintk("usb_xhci_port_on_attach: Failed to register root hub USB "
                "device!\n");
        usb_xhci_destroy_device(dev);
        return res;
    }

    printk("Finished Handling USB Device Attach!\n");
    return 0;
}

static int
usb_xhci_port_on_deattach(struct usb_xhci_port *port, uint32_t portsc)
{
    printk("Device Deattached from USB Port %lu\n",
           (ul_t)usb_xhci_port_index(port));
    return -EUNIMPL;
}

int
usb_xhci_port_notify_status_change(struct usb_xhci_port *port)
{
    if(port->status_change_tasklet)
    {
        return tasklet_trigger(port->status_change_tasklet);
    }
    else
    {
        return 0;
    }
}

static int
usb_xhci_dump_port(struct usb_xhci_port *port, printk_f *printer)
{
    uint32_t portsc = usb_xhci_port_read_portsc(port);
    unsigned link_state = (portsc >> 5) & 0xF;
    unsigned speed = (portsc >> 10) & 0xF;
    unsigned indicator = (portsc >> 14) & 0x3;
    (*printer)("PORT[%lu] {\n"
               "\tVersion=%d.%d\n"
               "\tConnected=%s\n"
               "\tEnabled=%s\n"
               "\tPowered=%s\n"
               "\tOver-Current=%s\n"
               "\tLink-State=%s\n"
               "\tSpeed=%u\n"
               "\tIndicator=%s\n"
               "}\n",
               (ul_t)usb_xhci_port_index(port),
               (int)port->version_major,
               (int)port->version_minor,
               portsc & (1ULL << 0) ? "YES" : "NO",
               portsc & (1ULL << 1) ? "YES" : "NO",
               portsc & (1ULL << 9) ? "YES" : "NO",
               portsc & (1ULL << 3) ? "YES" : "NO",
               link_state == 0    ? "U0 (Normal Operational)"
               : link_state == 1  ? "U1 (Receive/Transmit Circuitry Quiesced)"
               : link_state == 2  ? "U2 (Clock Possibly Quiesced)"
               : link_state == 3  ? "U3 (Suspend)"
               : link_state == 4  ? "Disabled"
               : link_state == 5  ? "RxDetect"
               : link_state == 6  ? "Inactive"
               : link_state == 7  ? "Polling"
               : link_state == 8  ? "Recovery"
               : link_state == 9  ? "Hot-Reset"
               : link_state == 10 ? "Compliance-Mode"
               : link_state == 11 ? "Test-Mode"
               : link_state == 15 ? "Resume"
                                  : "UNKNOWN",
               speed,
               indicator == 0   ? "OFF"
               : indicator == 1 ? "AMBER"
               : indicator == 2 ? "GREEN"
                                : "UNKNOWN");

    return 0;
}

static void
usb_xhci_port_handle_status_change(void *state)
{
    int res;

    struct usb_xhci_port *port = state;

    uint32_t portsc = usb_xhci_port_read_portsc(port);

    uint32_t portsc_clear = portsc;
    portsc_clear &= ~(1UL << 1); // Do not set the Enabled/Disabled bit
    portsc_clear &= ~(1UL << 4); // Do not set the Port reset bit
    portsc_clear &= ~(0xF << 5); // Clear the PLS field
    portsc_clear |= (1UL << 5);  // Set PLS to 1 (ignored by device)

    usb_xhci_port_write_portsc(port, portsc_clear); // Clear all changed events

    printk("XHCI: Port Status Change on Port %d\n", usb_xhci_port_index(port));
    usb_xhci_dump_port(port, do_printk);

    if(!(portsc & (1UL << 1)))
    {
        // The port is disabled,
        wprintk("XHCI: port status change ignored due to disable!\n");
        res = usb_xhci_enable_port(port);
        if(res)
        {
            wprintk("XHCI: Failed to enable USB port on port status change!\n");
            return;
        }
        printk("XHCI: Port Status Change on Port %d (After Enable)\n",
               usb_xhci_port_index(port));
        usb_xhci_dump_port(port, do_printk);
    }

    if(portsc & (1UL << 17))
    {
        // Connect Status Change
        int connected = portsc & (1UL << 0);
        if(connected)
        {
            usb_xhci_port_on_attach(port, portsc);
        }
        else
        {
            usb_xhci_port_on_deattach(port, portsc);
        }
    }
}

int
usb_xhci_dump_ports(struct usb_xhci *dev, printk_f *printer)
{
    int res;
    for(size_t i = 0; i < dev->num_ports; i++)
    {
        res = usb_xhci_dump_port(&dev->ports[i], printer);
        if(res)
        {
            return res;
        }
    }
    return 0;
}
