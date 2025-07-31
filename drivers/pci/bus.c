
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


    int reprobing = 0;
    ilist_node_t *list_node;
    ilist_for_each(list_node, &segment->bus_list) {
        struct pci_bus *bus = container_of(list_node, struct pci_bus, segment_node);
        if(bus->bus_index == bus_index) {
            reprobing = 1;
            break;
        }
    }

    if(reprobing) {
        // We already probed this Bus,
        // we cannot re-probe it without duplicating the struct
        // NOTE: We could refactor this later to allow reprobing safely,
        //       it just doesn't seem worthwhile right now.
        dprintk("Trying to re-probe PCI Segment %lu, Bus %lu. Currently this is unsupported.\n",
                (ul_t)segment->segment_id,
                (ul_t)bus_index);
        return 0;
    }

    struct pci_bus *bus = kmalloc(sizeof(struct pci_bus), KM_KERNEL);
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

