
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/port_cam.h>
#include <kanawha/init.h>
#include <kanawha/pio.h>

static inline uint32_t
port_pci_address(uint8_t bus, uint8_t device, uint8_t func, uint16_t offset)
{
    return (1ULL << 31) // Enable bit
           | ((uint32_t)bus << 16) | ((uint32_t)(device & 0x3F) << 11) |
           ((uint32_t)(func & 0x7) << 8) | ((uint32_t)(offset & 0xFF));
}

static int
port_pci_readb(struct pci_cam *cam,
               uint16_t seg,
               uint8_t bus,
               uint8_t device,
               uint8_t func,
               uint16_t offset,
               uint8_t *out)
{
    if(seg != 0)
    {
        return -EINVAL;
    }
    if(offset >= 0xFF)
    {
        return -EINVAL;
    }

    struct port_pci_cam *pcam = container_of(cam, struct port_pci_cam, cam);
    uint32_t addr = port_pci_address(bus, device, func, offset);
    outl(pcam->addr_port, addr);
    *out = inb(pcam->data_port);
    return 0;
}

static int
port_pci_readw(struct pci_cam *cam,
               uint16_t seg,
               uint8_t bus,
               uint8_t device,
               uint8_t func,
               uint16_t offset,
               uint16_t *out)
{
    if(seg != 0)
    {
        return -EINVAL;
    }
    if(offset >= 0xFF)
    {
        return -EINVAL;
    }

    struct port_pci_cam *pcam = container_of(cam, struct port_pci_cam, cam);
    uint32_t addr = port_pci_address(bus, device, func, offset);
    outl(pcam->addr_port, addr);
    *out = inw(pcam->data_port);
    return 0;
}

static int
port_pci_readl(struct pci_cam *cam,
               uint16_t seg,
               uint8_t bus,
               uint8_t device,
               uint8_t func,
               uint16_t offset,
               uint32_t *out)
{
    if(seg != 0)
    {
        return -EINVAL;
    }
    if(offset >= 0xFF)
    {
        return -EINVAL;
    }

    struct port_pci_cam *pcam = container_of(cam, struct port_pci_cam, cam);
    uint32_t addr = port_pci_address(bus, device, func, offset);
    outl(pcam->addr_port, addr);
    *out = inl(pcam->data_port);
    return 0;
}

static int
port_pci_writeb(struct pci_cam *cam,
                uint16_t seg,
                uint8_t bus,
                uint8_t device,
                uint8_t func,
                uint16_t offset,
                uint8_t in)
{
    if(seg != 0)
    {
        return -EINVAL;
    }
    if(offset >= 0xFF)
    {
        return -EINVAL;
    }

    struct port_pci_cam *pcam = container_of(cam, struct port_pci_cam, cam);
    uint32_t addr = port_pci_address(bus, device, func, offset);
    outl(pcam->addr_port, addr);
    outb(pcam->data_port, in);
    return 0;
}

static int
port_pci_writew(struct pci_cam *cam,
                uint16_t seg,
                uint8_t bus,
                uint8_t device,
                uint8_t func,
                uint16_t offset,
                uint16_t in)
{
    if(seg != 0)
    {
        return -EINVAL;
    }
    if(offset >= 0xFF)
    {
        return -EINVAL;
    }

    struct port_pci_cam *pcam = container_of(cam, struct port_pci_cam, cam);
    uint32_t addr = port_pci_address(bus, device, func, offset);
    outl(pcam->addr_port, addr);
    outw(pcam->data_port, in);
    return 0;
}

static int
port_pci_writel(struct pci_cam *cam,
                uint16_t seg,
                uint8_t bus,
                uint8_t device,
                uint8_t func,
                uint16_t offset,
                uint32_t in)
{
    if(seg != 0)
    {
        return -EINVAL;
    }
    if(offset >= 0xFF)
    {
        return -EINVAL;
    }

    struct port_pci_cam *pcam = container_of(cam, struct port_pci_cam, cam);
    uint32_t addr = port_pci_address(bus, device, func, offset);
    outl(pcam->addr_port, addr);
    outl(pcam->data_port, in);
    return 0;
}

int
register_port_pci_cam(struct port_pci_cam *cam,
                      pio_t addr_port,
                      pio_t data_port)
{
    cam->addr_port = addr_port;
    cam->data_port = data_port;

    return register_pci_cam(&cam->cam, 0);
}

const static struct pci_cam port_pci_cam_table = {
    .readb = port_pci_readb,
    .readw = port_pci_readw,
    .readl = port_pci_readl,
    .writeb = port_pci_writeb,
    .writew = port_pci_writew,
    .writel = port_pci_writel,
};

#define DEFAULT_PORT_PCI_ADDR_PORT 0xCF8
#define DEFAULT_PORT_PCI_DATA_PORT 0xCFC

static struct port_pci_cam default_port_cam = {
    .addr_port = DEFAULT_PORT_PCI_ADDR_PORT,
    .data_port = DEFAULT_PORT_PCI_DATA_PORT,
    .cam = port_pci_cam_table,
};
static int
register_default_port_pci_cam(void)
{
    int res;
    res = register_port_pci_cam(&default_port_cam,
                                DEFAULT_PORT_PCI_ADDR_PORT,
                                DEFAULT_PORT_PCI_DATA_PORT);
    if(res)
    {
        return res;
    }

    struct pci_segment *segment = pci_segment_create_or_get(0);
    if(segment == NULL)
    {
        eprintk("Failed to create or get PCI segment 0!\n");
        return -ENXIO;
    }

    res = pci_segment_probe(segment, 0, PCI_MAX_BUSES_PER_SEGMENT);
    if(res)
    {
        return res;
    }

    return 0;
}
declare_init_desc(early_device,
                  register_default_port_pci_cam,
                  "Registering Port PCI CAM");
