
#include <drivers/pci/cfg.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/list.h>


int
pci_probe_bus(
        struct pci_domain *domain,
        uint8_t bus_index)
{
    int res;

    printk("Enumerating PCI Domain %lu Bus %u\n",
            domain->domain_id, bus_index);

    struct pci_bus *bus = kmalloc(sizeof(struct pci_bus));
    if(bus == NULL) {
        return -ENOMEM;
    }
    bus->bus_index = bus_index;
    bus->domain = domain;
    ilist_init(&bus->device_list);
    
    ilist_push_tail(&domain->bus_list, &bus->domain_node);

    for(size_t dev_index = 0; dev_index < PCI_MAX_DEVICES_PER_BUS; dev_index++) {
        res = pci_probe_device(bus, dev_index);
        if(res) {
            return res;
        }
    }

    return 0;
}

