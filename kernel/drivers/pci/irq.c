
#include <drivers/pci/msi.h>
#include <drivers/pci/msix.h>

int
pci_func_init_irqs(
        struct pci_func *func)
{
    int res;

    // TODO INT-X

    res = pci_func_init_msi_info(func);
    if(res) {
        return res;
    }
    res = pci_func_init_msix_info(func);
    if(res) {
        pci_func_deinit_msi_info(func);
        return res;
    }
    return 0;
}

