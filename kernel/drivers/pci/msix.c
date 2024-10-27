
#include <drivers/pci/pci.h>
#include <drivers/pci/cap.h>
#include <drivers/pci/msix.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/string.h>

int
pci_func_init_msix_info(
        struct pci_func *func)
{
    struct pci_cap *cap = pci_func_find_cap(func, 0x11);
    if(cap == NULL) {
        func->msix_info = NULL;
        return 0;
    }

    struct pci_msix_info *info = kmalloc(sizeof(struct pci_msix_info));
    if(info == NULL) {
        return -ENOMEM;
    }
    memset(info, 0, sizeof(struct pci_msix_info));

    info->cap = cap;

    uint32_t bir_info = pci_cap_readb(func, cap, 0x4);
    uint8_t bir = bir_info & 0xFF;
    uint32_t bir_offset = bir_info & 0xFFFFFF00;

    if(bir >= 6) {
        return -EINVAL;
    }
    if(func->bars[bir].type != PCI_BAR_MMIO) {
        return -EINVAL;
    }
    info->bir = &func->bars[bir];
    info->bir_offset = bir_offset;

    uint32_t pending_bir_info = pci_cap_readb(func, cap, 0x8);
    uint8_t pending_bir = pending_bir_info & 0xFF;
    uint32_t pending_bir_offset = pending_bir_info & 0xFFFFFF00;
    if(pending_bir >= 6) {
        return -EINVAL;
    }
    if(func->bars[pending_bir].type != PCI_BAR_MMIO) {
        return -EINVAL;
    }
    info->pending_bir = &func->bars[bir];
    info->pending_bir_offset = pending_bir_offset;

    func->msix_info = info;
    printk("PCI Function has MSI-X Capability (BIR=0x%x, BIR-OFFSET=0x%x)\n",
            bir, bir_offset);

    return 0;
}

int
pci_func_deinit_msix_info(
        struct pci_func *func)
{
    if(func->msix_info) {
        kfree(func->msix_info);
        func->msix_info = NULL;
    }
    return 0;
}

size_t
pci_func_msix_max_num_irqs(
        struct pci_func *func)
{
    struct pci_msix_info *info = func->msix_info;
    if(info == NULL) {
        return 0;
    }

    uint16_t msg_ctrl = pci_cap_readw(func, info->cap, 0x2);
    uint16_t table_size = (msg_ctrl & ((1ULL<<11)-1)) + 1;
    return table_size;
}

size_t
pci_func_msix_num_irqs(
        struct pci_func *func)
{
    return pci_func_msix_max_num_irqs(func);
}

