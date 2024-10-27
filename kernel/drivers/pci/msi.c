
#include <drivers/pci/pci.h>
#include <drivers/pci/cap.h>
#include <drivers/pci/msi.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/string.h>

// init
int
pci_func_init_msi_info(
        struct pci_func *func)
{
    struct pci_cap *cap = pci_func_find_cap(func, 0x05);
    if(cap == NULL) {
        func->msi_info = NULL;
        return 0;
    }

    struct pci_msi_info *info = kmalloc(sizeof(struct pci_msi_info));
    if(info == NULL) {
        return -ENOMEM;
    }
    memset(info, 0, sizeof(struct pci_msi_info));

    info->cap = cap;

    func->msi_info = info;
    printk("PCI Function has MSI Capability\n");

    return 0;
}


// deinit
int
pci_func_deinit_msi_info(
        struct pci_func *func)
{
    if(func->msi_info) {
        kfree(func->msi_info);
        func->msi_info = NULL;
    }
    return 0;
}

// max_irqs

size_t
pci_func_msi_max_num_irqs(
        struct pci_func *func)
{
    struct pci_msi_info *info = func->msi_info;
    if(info == NULL) {
        return 0;
    }

    uint16_t msg_ctrl = pci_cap_readw(func, info->cap, 0x2);
    uint8_t mmc = (msg_ctrl >> 1) & 0b111;
    return 1ULL<<mmc;
}

size_t
pci_func_msi_num_irqs(
        struct pci_func *func)
{
    struct pci_msi_info *info = func->msi_info;
    if(info == NULL) {
        return 0;
    }

    uint16_t msg_ctrl = pci_cap_readw(func, info->cap, 0x2);
    uint8_t mme = (msg_ctrl >> 4) & 0b111;
    return 1ULL<<mme;
}

