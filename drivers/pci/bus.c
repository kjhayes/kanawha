
#include <drivers/pci/cfg.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>

int
pci_probe_bus(struct pci_segment *segment, uint8_t bus_index)
{
    int res;

    struct pci_bus *bus = NULL;
    struct ptree_node *bus_tree_node = ptree_get(&segment->bus_tree, bus_index);
    if(bus_tree_node != NULL)
    {
        bus = container_of(bus_tree_node, struct pci_bus, segment_node);
    }

    dprintk("Enumerating PCI Segment %lu Bus %u\n",
            segment->segment_id,
            bus_index);

    if(bus != NULL)
    {
        // We already probed this Bus,
        // we cannot re-probe it without duplicating the struct
        // NOTE: We could refactor this later to allow reprobing safely,
        //       it just doesn't seem worthwhile right now.
        dprintk("Trying to re-probe PCI Segment %lu, Bus %lu. Currently this "
                "is unsupported.\n",
                (ul_t)segment->segment_id,
                (ul_t)bus_index);
        return 0;
    }
    else
    {

        bus = kmalloc(sizeof(struct pci_bus), KM_KERNEL);
        if(bus == NULL)
        {
            return -ENOMEM;
        }
        bus->bus_index = bus_index;
        bus->segment = segment;

        ptree_init(&bus->device_tree);
        ptree_insert(&segment->bus_tree, &bus->segment_node, bus_index);
    }

    // Do the enumeration
    for(size_t dev_index = 0; dev_index < PCI_MAX_DEVICES_PER_BUS; dev_index++)
    {
        res = pci_probe_device(bus, dev_index);
        if(res == -ENXIO)
        {
#ifdef CONFIG_PCI_ASSUME_CONTIGUOUS_DEVICES
            break;
#endif
        }
        else if(res)
        {
            wprintk("Failed to probe PCI device (bus=%lu, "
                    "device=%lu) (err=%s)\n",
                    (ul_t)bus,
                    (ul_t)dev_index,
                    errnostr(res));
        }
    }

    return 0;
}
