
#include <drivers/pci/pci.h>
#include <drivers/pci/cfg.h>
#include <kanawha/mmio.h>

#ifdef CONFIG_PORT_IO
#include <kanawha/pio.h>
#endif

uint8_t pci_bar_readb(struct pci_bar *bar, size_t offset)
{
    switch(bar->type) {
        case PCI_BAR_MMIO:
            return mmio_readb(bar->mmio.base + offset);
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            return inb(bar->pio.base + offset);
#endif
        case PCI_BAR_NONE:
            return 0;
    }
}
uint16_t pci_bar_readw(struct pci_bar *bar, size_t offset)
{
    switch(bar->type) {
        case PCI_BAR_MMIO:
            return mmio_readw(bar->mmio.base + offset);
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            return inw(bar->pio.base + offset);
#endif
        case PCI_BAR_NONE:
            return 0;
    }
}
uint32_t pci_bar_readl(struct pci_bar *bar, size_t offset)
{
    switch(bar->type) {
        case PCI_BAR_MMIO:
            return mmio_readl(bar->mmio.base + offset);
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            return inl(bar->pio.base + offset);
#endif
        case PCI_BAR_NONE:
            return 0;
    }
}
uint64_t pci_bar_readq(struct pci_bar *bar, size_t offset)
{
    switch(bar->type) {
        case PCI_BAR_MMIO:
            return mmio_readq(bar->mmio.base + offset);
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            eprintk("Tried to read 64-bit value from a Port I/O PCI BAR!\n");
            return 0;
#endif
        case PCI_BAR_NONE:
            return 0;
    }
}

void pci_bar_writeb(struct pci_bar *bar, size_t offset, uint8_t val)
{
    switch(bar->type) {
        case PCI_BAR_MMIO:
            mmio_writeb(bar->mmio.base + offset, val);
            break;
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            outb(bar->pio.base + offset, val);
            break;
#endif
        case PCI_BAR_NONE:
            break;
    }
}
void pci_bar_writew(struct pci_bar *bar, size_t offset, uint16_t val)
{
    switch(bar->type) {
        case PCI_BAR_MMIO:
            mmio_writew(bar->mmio.base + offset, val);
            break;
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            outw(bar->pio.base + offset, val);
            break;
#endif
        case PCI_BAR_NONE:
            break;
    }
}
void pci_bar_writel(struct pci_bar *bar, size_t offset, uint32_t val)
{
    switch(bar->type) {
        case PCI_BAR_MMIO:
            mmio_writel(bar->mmio.base + offset, val);
            break;
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            outl(bar->pio.base + offset, val);
            break;
#endif
        case PCI_BAR_NONE:
            break;
    }
}
void pci_bar_writeq(struct pci_bar *bar, size_t offset, uint64_t val)
{
    switch(bar->type) {
        case PCI_BAR_MMIO:
            mmio_writeq(bar->mmio.base + offset, val);
            break;
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            eprintk("Tried to write 64-bit value to a Port I/O PCI BAR!\n");
            break;
#endif
        case PCI_BAR_NONE:
            break;
    }
}

