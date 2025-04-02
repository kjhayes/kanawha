
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
        struct pci_domain *domain,
        size_t assumed_bus_start,
        size_t assumed_bus_count) 
{
    int res;
    for(size_t bus_index = 0; bus_index < assumed_bus_count; bus_index++) {
        size_t bus = assumed_bus_start + bus_index;
        res = pci_probe_bus(domain, bus);
        if(res) {
            wprintk("Failed to probe PCI bus %lu! (err=%s)\n",
                    (ul_t)bus,
                    errnostr(res));
        }
    }
    return 0;
}

int
register_pci_domain(
        struct pci_domain *domain,
        struct pci_cam *cam)
{
    return register_pci_domain_with_assumed_buses(
            domain,
            cam,
            0,
            1);
}

int
register_pci_domain_with_assumed_buses(
        struct pci_domain *domain,
        struct pci_cam *cam,
        size_t assumed_bus_start,
        size_t assumed_bus_count)
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
    res = pci_domain_enumerate(domain, assumed_bus_start, assumed_bus_count);
    if(res) {
        eprintk("Encountered error (%s) when enumerating devices of PCI Domain %lu!\n",
                errnostr(res), domain->domain_id);
        return res;
    }

    return 0;
}

