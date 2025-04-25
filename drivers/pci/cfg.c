
#include <drivers/pci/pci.h>
#include <drivers/pci/cfg.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/list.h>

static DECLARE_SPINLOCK(pci_segment_list_lock);
static DECLARE_ILIST(pci_segment_list);

static int
pci_segment_enumerate(
        struct pci_segment *segment,
        size_t assumed_bus_start,
        size_t assumed_bus_count) 
{
    int res;
    for(size_t bus_index = 0; bus_index < assumed_bus_count; bus_index++) {
        size_t bus = assumed_bus_start + bus_index;
        res = pci_probe_bus(segment, bus);
        if(res) {
            wprintk("Failed to probe PCI bus %lu! (err=%s)\n",
                    (ul_t)bus,
                    errnostr(res));
        }
    }
    return 0;
}

int
register_pci_cam(
        uint16_t segment_id,
        struct pci_cam *cam)
{
    return register_pci_cam_with_assumed_buses(
            segment_id,
            cam,
            0,
            256);
}

int
register_pci_cam_with_assumed_buses(
        uint16_t segment_id,
        struct pci_cam *cam,
        size_t assumed_bus_start,
        size_t assumed_bus_count)
{
    int res;

    struct pci_segment *segment = NULL;

    spin_lock(&pci_segment_list_lock);
    ilist_node_t *node;
    ilist_for_each(node, &pci_segment_list) {
        struct pci_segment *seg = container_of(node, struct pci_segment, global_node);
        if(seg->segment_id == segment_id) {
            spin_lock(&seg->cam_lock);
            ilist_push_head(&seg->cam_list, &cam->segment_node);
            segment = seg;
            spin_unlock(&seg->cam_lock);
            break;
        }
    }
    if(segment == NULL) {
        segment = kmalloc(sizeof(struct pci_segment));
        if(segment == NULL) {
            spin_unlock(&pci_segment_list_lock);    
            return -ENOMEM;
        }
        ilist_init(&segment->bus_list);
        ilist_init(&segment->cam_list);
        spinlock_init(&segment->cam_lock);

        segment->segment_id = segment_id;
        ilist_push_tail(&segment->cam_list, &cam->segment_node);
    }
    spin_unlock(&pci_segment_list_lock);    

    printk("Registered PCI Segment %lu\n", segment->segment_id);

    // Enumerate the devices we find in the segment
    res = pci_segment_enumerate(segment, assumed_bus_start, assumed_bus_count);
    if(res) {
        eprintk("Encountered error (%s) when enumerating devices of PCI Segment %lu!\n",
                errnostr(res), segment->segment_id);
        return res;
    }

    return 0;
}

