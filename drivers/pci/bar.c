
#include <drivers/pci/pci.h>
#include <drivers/pci/cfg.h>
#include <kanawha/mmio.h>

#ifdef CONFIG_PORT_IO
#include <kanawha/pio.h>
#endif

#ifdef CONFIG_DEBUG_LOG_PCI_BAR_ACCESSES
#define DEBUG_LOG(...) printk(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

#ifdef CONFIG_DEBUG_PCI_BAR_ACCESSES
#define DEBUG_CHECK_BOUNDS(__bar, __offset, __size)\
    DEBUG_ASSERT((__bar->size) >= ((__offset) + (__size)))
#else
#define DEBUG_CHECK_BOUNDS(__bar, __offset, __size)
#endif

uint8_t pci_bar_readb(struct pci_bar *bar, size_t offset)
{
    DEBUG_CHECK_BOUNDS(bar, offset, 1);
    switch(bar->type) {
        case PCI_BAR_MMIO:
            DEBUG_LOG("PCI BAR MMIO 8-bit Read: offset=%p, phys_addr=%p\n",
                    offset, bar->phys_addr + offset);
            return mmio_readb(bar->mmio.base + offset);
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            return inb(bar->pio.base + offset);
#endif
        case PCI_BAR_NONE:
            panic("pci_bar_readb on PCI_BAR_NONE!");
            return 0;
    }
    panic("pci_bar_readb on invalid PCI BAR!");
    return 0;
}
uint16_t pci_bar_readw(struct pci_bar *bar, size_t offset)
{
    DEBUG_CHECK_BOUNDS(bar, offset, 2);
    switch(bar->type) {
        case PCI_BAR_MMIO:
            DEBUG_LOG("PCI BAR MMIO 16-bit Read: offset=%p, phys_addr=%p\n",
                    offset, bar->phys_addr + offset);
            return mmio_readw(bar->mmio.base + offset);
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            return inw(bar->pio.base + offset);
#endif
        case PCI_BAR_NONE:
            panic("pci_bar_readw on PCI_BAR_NONE!");
            return 0;
    }
    panic("pci_bar_readw on invalid PCI BAR!");
    return 0;
}
uint32_t pci_bar_readl(struct pci_bar *bar, size_t offset)
{
    DEBUG_CHECK_BOUNDS(bar, offset, 4);
    switch(bar->type) {
        case PCI_BAR_MMIO:
            DEBUG_LOG("PCI BAR MMIO 32-bit Read: offset=%p, phys_addr=%p\n",
                    offset, bar->phys_addr + offset);
            return mmio_readl(bar->mmio.base + offset);
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            return inl(bar->pio.base + offset);
#endif
        case PCI_BAR_NONE:
            panic("pci_bar_readl on PCI_BAR_NONE!");
            return 0;
    }
    panic("pci_bar_readw on invalid PCI BAR!");
    return 0;
}
uint64_t pci_bar_readq(struct pci_bar *bar, size_t offset)
{
    DEBUG_CHECK_BOUNDS(bar, offset, 8);
    switch(bar->type) {
        case PCI_BAR_MMIO:
            DEBUG_LOG("PCI BAR MMIO 64-bit Read: offset=%p, phys_addr=%p\n",
                    offset, bar->phys_addr + offset);
            return mmio_readq(bar->mmio.base + offset);
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            eprintk("Tried to read 64-bit value from a Port I/O PCI BAR!\n");
            return 0;
#endif
        case PCI_BAR_NONE:
            panic("pci_bar_readq on PCI_BAR_NONE!");
            return 0;
    }
    panic("pci_bar_readq on invalid PCI BAR!");
    return 0;
}

void pci_bar_writeb(struct pci_bar *bar, size_t offset, uint8_t val)
{
    DEBUG_CHECK_BOUNDS(bar, offset, 1);
    switch(bar->type) {
        case PCI_BAR_MMIO:
            DEBUG_LOG("PCI BAR MMIO 8-bit Write: offset=%p, phys_addr=%p\n",
                    offset, bar->phys_addr + offset);
            mmio_writeb(bar->mmio.base + offset, val);
            break;
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            outb(bar->pio.base + offset, val);
            break;
#endif
        case PCI_BAR_NONE:
            panic("pci_bar_writeb on PCI_BAR_NONE!");
            break;
    }
}
void pci_bar_writew(struct pci_bar *bar, size_t offset, uint16_t val)
{
    DEBUG_CHECK_BOUNDS(bar, offset, 2);
    switch(bar->type) {
        case PCI_BAR_MMIO:
            DEBUG_LOG("PCI BAR MMIO 16-bit Write: offset=%p, phys_addr=%p\n",
                    offset, bar->phys_addr + offset);
            mmio_writew(bar->mmio.base + offset, val);
            break;
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            outw(bar->pio.base + offset, val);
            break;
#endif
        case PCI_BAR_NONE:
            panic("pci_bar_writew on PCI_BAR_NONE!");
            break;
    }
}
void pci_bar_writel(struct pci_bar *bar, size_t offset, uint32_t val)
{
    DEBUG_CHECK_BOUNDS(bar, offset, 4);

    switch(bar->type) {
        case PCI_BAR_MMIO:
            DEBUG_LOG("PCI BAR MMIO 32-bit Write: offset=%p, phys_addr=%p\n",
                    offset, bar->phys_addr + offset);
            mmio_writel(bar->mmio.base + offset, val);
            break;
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            outl(bar->pio.base + offset, val);
            break;
#endif
        case PCI_BAR_NONE:
            panic("pci_bar_writel on PCI_BAR_NONE!");
            break;
    }
}
void pci_bar_writeq(struct pci_bar *bar, size_t offset, uint64_t val)
{
    DEBUG_CHECK_BOUNDS(bar, offset, 8);
    switch(bar->type) {
        case PCI_BAR_MMIO:
            DEBUG_LOG("PCI BAR MMIO 64-bit Write: offset=%p, phys_addr=%p\n",
                    offset, bar->phys_addr + offset);
            mmio_writeq(bar->mmio.base + offset, val);
            break;
#ifdef CONFIG_PORT_IO
        case PCI_BAR_PIO:
            eprintk("Tried to write 64-bit value to a Port I/O PCI BAR!\n");
            break;
#endif
        case PCI_BAR_NONE:
            panic("pci_bar_writeq on PCI_BAR_NONE!");
            break;
    }
}

