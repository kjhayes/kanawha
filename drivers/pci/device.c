
#include <kanawha/types.h>
#include <kanawha/kmalloc.h>
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>

int
pci_probe_device(
        struct pci_bus *bus,
        uint8_t dev_index)
{
    int res;

    uint16_t probe_id;
    pci_bus_readw(bus, dev_index, 0, PCI_CFG_VENDOR_ID, &probe_id);
    if(probe_id == 0xFFFF) {
        // Device does not exist
        return -ENXIO;
    }

    struct pci_device *device;
    device = kmalloc(sizeof(struct pci_device));
    if(device == NULL) {
        kfree(device);
        return -ENOMEM;
    }
    device->segment = bus->segment;
    device->bus = bus;
    device->index = dev_index;
    ilist_init(&device->function_list);

    ilist_push_tail(&bus->device_list, &device->bus_node);

    // Iterate over the functions
    uint8_t func_index = 0;
    while(func_index < PCI_MAX_FUNC_PER_DEVICE)
    {
        res = pci_probe_func(
                device,
                func_index);
        if(res == -ENXIO) {
            break;
        } else if(res) {
            wprintk("Failed to probe PCI function (bus=%lu, device=%lu, func=%lu) (err=%s)\n",
                    (ul_t)bus->bus_index,
                    (ul_t)dev_index,
                    (ul_t)func_index,
                    errnostr(res));
        }
        func_index++;
    }

    return 0;
}

