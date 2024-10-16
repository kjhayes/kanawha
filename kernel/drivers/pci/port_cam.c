
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <kanawha/pio.h>
#include <kanawha/init.h>

#define PORT_PCI_ADDR_PORT 0xCF8
#define PORT_PCI_DATA_PORT 0xCFC

static inline uint32_t
port_pci_address(
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset)
{
    return (1ULL<<31) // Enable bit
        |  ((uint32_t)bus << 16)
        |  ((uint32_t)(device & 0x3F) << 11)
        |  ((uint32_t)(func & 0x7) << 8)
        |  ((uint32_t)(offset & 0xFF));
}

static int
port_pci_readb(
        struct pci_domain *domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t *out
        )
{
    uint32_t addr = port_pci_address(bus,device,func,offset);
    outl(PORT_PCI_ADDR_PORT, addr);
    *out = inb(PORT_PCI_DATA_PORT);
    return 0;
}

static int
port_pci_readw(
        struct pci_domain *domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t *out
        )
{
    uint32_t addr = port_pci_address(bus,device,func,offset);
    outl(PORT_PCI_ADDR_PORT, addr);
    *out = inw(PORT_PCI_DATA_PORT);
    return 0;
}

static int
port_pci_readl(
        struct pci_domain *domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t *out
        )
{
    uint32_t addr = port_pci_address(bus,device,func,offset);
    outl(PORT_PCI_ADDR_PORT, addr);
    *out = inl(PORT_PCI_DATA_PORT);
    return 0;
}

static int
port_pci_writeb(
        struct pci_domain *domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t in 
        )
{
    uint32_t addr = port_pci_address(bus,device,func,offset);
    outl(PORT_PCI_ADDR_PORT, addr);
    outb(PORT_PCI_DATA_PORT, in);
    return 0;
}

static int
port_pci_writew(
        struct pci_domain *domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t in 
        )
{
    uint32_t addr = port_pci_address(bus,device,func,offset);
    outl(PORT_PCI_ADDR_PORT, addr);
    outw(PORT_PCI_DATA_PORT, in);
    return 0;
}

static int
port_pci_writel(
        struct pci_domain *domain,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t in 
        )
{
    uint32_t addr = port_pci_address(bus,device,func,offset);
    outl(PORT_PCI_ADDR_PORT, addr);
    outl(PORT_PCI_DATA_PORT, in);
    return 0;
}

static struct pci_cam
port_pci_cam = {
    .readb   = port_pci_readb,
    .readw  = port_pci_readw,
    .readl  = port_pci_readl,
    .writeb  = port_pci_writeb,
    .writew = port_pci_writew,
    .writel = port_pci_writel,
};

static struct pci_domain
port_pci_domain = { 0 };

static int
register_port_pci_cam_domain(void)
{
    return register_pci_domain(
            &port_pci_domain,
            &port_pci_cam);

}
declare_init_desc(bus, register_port_pci_cam_domain, "Registering Port PCI Domain");

