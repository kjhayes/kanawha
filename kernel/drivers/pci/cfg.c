
#include <drivers/pci/pci.h>
#include <drivers/pci/cfg.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/list.h>

static DECLARE_SPINLOCK(pci_domain_list_lock);
static DECLARE_ILIST(pci_domain_list);
static size_t __next_domain_id = 0;

static int
pci_domain_enumerate(
        struct pci_domain *domain) 
{
    // We assume Bus 0 exists, and we will recursively search for devices/buses from there
    return pci_probe_bus(domain, 0);
}

int
register_pci_domain(
        struct pci_domain *domain,
        struct pci_cam *cam)
{
    int res;

    spin_lock(&pci_domain_list_lock);
    domain->domain_id = __next_domain_id;
    domain->cam = cam;
    __next_domain_id++;
    ilist_push_tail(&pci_domain_list, &domain->global_node);
    spin_unlock(&pci_domain_list_lock);    

    ilist_init(&domain->bus_list);

    printk("Registered PCI Domain %lu\n", domain->domain_id);

    // Enumerate the devices we find on the bus
    res = pci_domain_enumerate(domain);
    if(res) {
        eprintk("Encountered error (%s) when enumerating devices of PCI Domain %lu!\n",
                errnostr(res), domain->domain_id);
        return res;
    }

    return 0;
}

