
#include <drivers/pci/cfg.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/list.h>


int
pci_probe_bus(
        struct pci_segment *segment,
        uint8_t bus_index)
{
    int res;

    dprintk("Enumerating PCI Segment %lu Bus %u\n",
            segment->segment_id, bus_index);

    struct pci_bus *bus = kmalloc(sizeof(struct pci_bus));
    if(bus == NULL) {
        return -ENOMEM;
    }
    bus->bus_index = bus_index;
    bus->segment = segment;
    ilist_init(&bus->device_list);
    
    ilist_push_tail(&segment->bus_list, &bus->segment_node);

    for(size_t dev_index = 0; dev_index < PCI_MAX_DEVICES_PER_BUS; dev_index++) {
        res = pci_probe_device(bus, dev_index);
        if(res == -ENXIO) {
#ifdef CONFIG_PCI_ASSUME_CONTIGUOUS_DEVICES
            break;
#endif
        }
        else if(res) {
            wprintk("Failed to probe PCI device (bus=%lu, device=%lu) (err=%s)\n",
                    (ul_t)bus,
                    (ul_t)dev_index,
                    errnostr(res));
        }
    }

    return 0;
}

