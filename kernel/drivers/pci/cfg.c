
#include <drivers/pci/pci.h>
#include <drivers/pci/cfg.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>

static DECLARE_SPINLOCK(pci_domain_list_lock);
static DECLARE_ILIST(pci_domain_list);
static size_t __next_domain_id = 0;

static int
pci_domain_read_name(
        struct device *dev,
        char *buf,
        size_t size)
{
    struct pci_domain *domain =
        container_of(dev, struct pci_domain, dev);

    snprintk(buf, size, "pci-dom-%lu", (unsigned long)domain->domain_id);
    return 0;
}

static int
pci_bus_read_name(
        struct device *dev,
        char *buf,
        size_t size)
{
    struct pci_bus *bus =
        container_of(dev, struct pci_bus, dev);

    snprintk(buf, size, "pci-bus-%u", (unsigned)bus->bus_index);
    return 0;
}

static int
pci_device_read_name(
        struct device *dev,
        char *buf,
        size_t size)
{
    struct pci_device *pdev=
        container_of(dev, struct pci_device, dev);

    snprintk(buf, size, "pci-%u.%u-%x:%x",
            pdev->dev_index, pdev->func_index,
            pdev->vendor_id, pdev->device_id);
    return 0;
}

static struct device_ops
pci_domain_dev_ops = {
    .read_name = pci_domain_read_name,
};

static struct device_ops
pci_bus_dev_ops = {
    .read_name = pci_bus_read_name,
};

static struct device_ops
pci_device_ops = {
    .read_name = pci_device_read_name,
};

static int
pci_domain_register_bus(
        struct pci_domain *domain,
        uint8_t bus_index)
{
    printk("Enumerating PCI Domain %lu Bus %u\n",
            domain->domain_id, bus_index);

    struct pci_bus *bus = kmalloc(sizeof(struct pci_bus));
    if(bus == NULL) {
        return -ENOMEM;
    }
    bus->bus_index = bus_index;
    bus->domain = domain;

    int res = register_device(
            &bus->dev,
            &pci_bus_dev_ops,
            &domain->dev);

    if(res) {
        kfree(bus);
        return res;
    }

    res = 0;
    for(size_t dev_index = 0; dev_index < PCI_MAX_DEVICES_PER_BUS; dev_index++) {
        uint8_t func = 0;

        uint16_t vendor_id;

        do {
            pci_bus_read16(bus, dev_index, func, PCI_CFG_VENDOR_ID, &vendor_id);

            if(vendor_id != 0xFFFF) {

                struct pci_device *dev = kmalloc(sizeof(struct pci_device));
                if(dev == NULL) {
                    eprintk("Failed to allocate PCI device struct!\n");
                    res = -ENOMEM;
                    break;
                }

                dev->domain = domain;
                dev->bus = bus;
                dev->dev_index = dev_index;
                dev->func_index = func;

                pci_bus_read16(bus, dev_index, func, PCI_CFG_VENDOR_ID, &dev->vendor_id);
                pci_bus_read16(bus, dev_index, func, PCI_CFG_DEVICE_ID, &dev->device_id);

                res = register_device(
                        &dev->dev,
                        &pci_device_ops,
                        &bus->dev);
                if(res) {
                    eprintk("Failed to register PCI device!\n");
                    break;
                }

                uint8_t hdr_type;
                pci_device_read8(dev, PCI_CFG_HEADER_TYPE, &hdr_type);

                if((hdr_type & 0x7F) == PCI_HEADER_TYPE_PCI_PCI_BRIDGE) {
                    // Cross the PCI bridge
                    uint8_t sec_bus;
                    printk("Found PCI-to-PCI Bridge\n");
                    pci_device_read8(dev, PCI_CFG_PCI_BRIDGE_SECONDARY_BUS, &sec_bus);
                    res = pci_domain_register_bus(domain, sec_bus);
                    if(res) {
                        eprintk("Failed to enumerate secondary PCI bus %u of domain %lu\n",
                                sec_bus, domain->domain_id);
                    }
                }

                if(func == 0 && (hdr_type & 0x80) != 0x80) {
                    // Not a multifunction device
                    break;
                }

                // This is a multifunction device, check the next function
                func++;
            } else {
                break;
            }
        } while(func < PCI_MAX_FUNC_PER_DEVICE);
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
    ilist_push_tail(&pci_domain_list, &domain->list_node);
    spin_unlock(&pci_domain_list_lock);    


    res = register_device(
            &domain->dev,
            &pci_domain_dev_ops,
            NULL);
    if(res) {
        return res;
    }

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

