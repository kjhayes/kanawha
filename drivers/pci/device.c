
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <kanawha/kmalloc.h>
#include <kanawha/types.h>

int
pci_probe_device(struct pci_bus *bus, uint8_t dev_index)
{
    int res;

    struct pci_device *device = NULL;
    struct ptree_node *bus_tree_node = ptree_get(&bus->device_tree, dev_index);
    if(bus_tree_node != NULL)
    {
        device = container_of(bus_tree_node, struct pci_device, bus_node);
    }

    uint16_t probe_id;
    pci_bus_readw(bus, dev_index, 0, PCI_CFG_VENDOR_ID, &probe_id);
    if(probe_id == 0xFFFF)
    {
        // Device does not exist
        if(device != NULL)
        {
            panic("PCI Device Stopped Existing on Re-probe!\n");
        }
        return -ENXIO;
    }

    if(device == NULL)
    {
        device = kmalloc(sizeof(struct pci_device), KM_KERNEL);
        if(device == NULL)
        {
            kfree(device);
            return -ENOMEM;
        }
        device->segment = bus->segment;
        device->bus = bus;
        device->index = dev_index;

        ptree_init(&device->function_tree);

        ptree_insert(&bus->device_tree, &device->bus_node, dev_index);
    }

    // Iterate over the functions
    uint8_t func_index = 0;
    while(func_index < PCI_MAX_FUNC_PER_DEVICE)
    {
        res = pci_probe_func(device, func_index);
        if(res == -ENXIO)
        {
            break;
        }
        else if(res)
        {
            wprintk("Failed to probe PCI function (bus=%lu, device=%lu, "
                    "func=%lu) (err=%s)\n",
                    (ul_t)bus->bus_index,
                    (ul_t)dev_index,
                    (ul_t)func_index,
                    errnostr(res));
        }
        func_index++;
    }

    return 0;
}
