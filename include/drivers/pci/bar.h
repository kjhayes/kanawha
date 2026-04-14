#ifndef __KANAWHA__PCI_BAR_H__
#define __KANAWHA__PCI_BAR_H__

#include <kanawha/mmio.h>
#include <kanawha/types.h>
#include <kanawha/pio.h>

struct pci_bar
{
    size_t size;
    void __phys *phys_addr;

    enum
    {
        PCI_BAR_UNINIT = 0,
        PCI_BAR_NONE,
        PCI_BAR_MMIO,
        PCI_BAR_PIO,
    } type;

    union
    {
        struct
        {
            void __mmio *base;
            unsigned prefetch : 1;
            unsigned type : 2;
        } mmio;

        struct
        {
            pio_t base;
        } pio;
    };
};

uint8_t
pci_bar_readb(struct pci_bar *bar, size_t offset);
uint16_t
pci_bar_readw(struct pci_bar *bar, size_t offset);
uint32_t
pci_bar_readl(struct pci_bar *bar, size_t offset);
uint64_t
pci_bar_readq(struct pci_bar *bar, size_t offset);

void
pci_bar_writeb(struct pci_bar *bar, size_t offset, uint8_t val);
void
pci_bar_writew(struct pci_bar *bar, size_t offset, uint16_t val);
void
pci_bar_writel(struct pci_bar *bar, size_t offset, uint32_t val);
void
pci_bar_writeq(struct pci_bar *bar, size_t offset, uint64_t val);

#endif
