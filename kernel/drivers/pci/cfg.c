
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
pci_domain_register_bus(
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

    res = 0;
    for(size_t dev_index = 0; dev_index < PCI_MAX_DEVICES_PER_BUS; dev_index++) {
        uint8_t func_index = 0;

        uint16_t vendor_id;

        struct pci_device *device = NULL;

        do {
            pci_bus_read16(bus, dev_index, func_index, PCI_CFG_VENDOR_ID, &vendor_id);

            if(vendor_id != 0xFFFF) {

                struct pci_func *func = kmalloc(sizeof(struct pci_func));
                if(func == NULL) {
                    eprintk("Failed to allocate PCI device struct!\n");
                    res = -ENOMEM;
                    break;
                }

                func->domain = domain;
                func->index = func_index;

                if(device == NULL) {
                    device = kmalloc(sizeof(struct pci_device));
                    if(device == NULL) {
                        kfree(func);
                        res = -ENOMEM;
                        break;
                    }
                    device->domain = domain;
                    device->bus = bus;
                    device->index = dev_index;
                    ilist_init(&device->function_list);

                    ilist_push_tail(&bus->device_list, &device->bus_node);
                }

                ilist_push_tail(&device->function_list, &func->device_node);
                func->device = device;

                pci_bus_read16(bus, dev_index, func_index, PCI_CFG_VENDOR_ID, &func->vendor_id);
                pci_bus_read16(bus, dev_index, func_index, PCI_CFG_DEVICE_ID, &func->device_id);

                uint8_t hdr_type;
                pci_func_read8(func, PCI_CFG_HEADER_TYPE, &hdr_type);

                printk("PCI Function: 0x%x:0x%x -> ID(0x%x:0x%x)\n",
                        dev_index, func_index, func->vendor_id, func->device_id);


                if((hdr_type & 0x7F) == PCI_HEADER_TYPE_PCI_PCI_BRIDGE) {
                    // Cross the PCI bridge
                    uint8_t sec_bus;
                    printk("Found PCI-to-PCI Bridge\n");
                    pci_func_read8(func, PCI_CFG_PCI_BRIDGE_SECONDARY_BUS, &sec_bus);
                    res = pci_domain_register_bus(domain, sec_bus);
                    if(res) {
                        eprintk("Failed to enumerate secondary PCI bus %u of domain %lu\n",
                                sec_bus, domain->domain_id);
                    }
                }

                if(func_index == 0 && (hdr_type & 0x80) != 0x80) {
                    // Not a multifunction device
                    break;
                }

                // This is a multifunction device, check the next function
                func_index++;
            } else {
                break;
            }
        } while(func_index < PCI_MAX_FUNC_PER_DEVICE);
    }

    return res;
}

static int
pci_domain_enumerate(
        struct pci_domain *domain) 
{
    // We assume Bus 0 exists, and we will recursively search for devices/buses from there
    return pci_domain_register_bus(domain, 0);
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

