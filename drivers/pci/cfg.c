
#include <drivers/pci/pci.h>
#include <drivers/pci/cfg.h>
#include <kanawha/list.h>
#include <kanawha/spinlock.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/list.h>
#include <kanawha/rwlock.h>

static DECLARE_SPINLOCK(pci_segment_list_lock);
static DECLARE_ILIST(pci_segment_list);

static DECLARE_RLOCK(pci_cam_list_lock);
static DECLARE_ILIST(pci_cam_list);

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
        struct pci_cam *cam,
        unsigned long flags)
{
    cam->flags = flags;
    rlock_write_lock(&pci_cam_list_lock);

    ilist_push_tail(&pci_cam_list, &cam->global_node);

    rlock_write_unlock(&pci_cam_list_lock);
    return 0;
}

int
pci_probe_segment(
        uint16_t segment_id)
{
    return pci_probe_segment_with_assumed_buses(
            segment_id,
            0,
            PCI_MAX_BUSES_PER_SEGMENT);
}

int
pci_probe_segment_with_assumed_buses(
        uint16_t segment_id,
        size_t assumed_bus_start,
        size_t assumed_bus_count)
{
    int res;

    struct pci_segment *segment = NULL;

    // Find the segment if it already exists, or create a new structure for it
    spin_lock(&pci_segment_list_lock);
    ilist_node_t *node;
    ilist_for_each(node, &pci_segment_list) {
        struct pci_segment *seg = container_of(node, struct pci_segment, global_node);
        if(seg->segment_id == segment_id) {
            segment = seg;
            break;
        }
    }
    
    // The segment does not already exist, create it
    if(segment == NULL) {
        printk("Registering PCI Segment %lu\n", segment_id);

        segment = kmalloc(sizeof(struct pci_segment), KM_KERNEL);
        if(segment == NULL) {
            eprintk("Ran out of memory when allocating PCI segment struct!\n");
            spin_unlock(&pci_segment_list_lock); 
            return -ENOMEM;
        }
        ilist_init(&segment->bus_list);

        segment->segment_id = segment_id;

        ilist_push_tail(&pci_segment_list, &segment->global_node);
    }
    spin_unlock(&pci_segment_list_lock);    

    // This should never happen (should have failed before this)
    if(segment == NULL) {
        eprintk("Failed to find/create PCI segment %lu!\n", segment_id);
        return -ENXIO;
    }

    printk("Probing PCI Segment %lu\n", segment->segment_id);

    // Enumerate the devices we find in the segment
    res = pci_segment_enumerate(segment, assumed_bus_start, assumed_bus_count);
    if(res) {
        eprintk("Encountered error (%s) when enumerating devices of PCI Segment %lu!\n",
                errnostr(res), segment->segment_id);
        return res;
    }

    return 0;
}

int
pci_segment_readb(
        struct pci_segment *segment,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t *out)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list) {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_readb(
                cam,
                segment->segment_id,
                bus,
                device,
                func,
                offset,
                out);
        if(res == 0) {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int
pci_segment_readw(
        struct pci_segment *segment,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t *out)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list) {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_readw(
                cam,
                segment->segment_id,
                bus,
                device,
                func,
                offset,
                out);
        if(res == 0) {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int
pci_segment_readl(
        struct pci_segment *segment,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t *out)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list) {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_readl(
                cam,
                segment->segment_id,
                bus,
                device,
                func,
                offset,
                out);
        if(res == 0) {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int
pci_segment_writeb(
        struct pci_segment *segment,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint8_t in)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list) {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_writeb(
                cam,
                segment->segment_id,
                bus,
                device,
                func,
                offset,
                in);
        if(res == 0) {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int
pci_segment_writew(
        struct pci_segment *segment,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint16_t in)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);
    
    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list) {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_writew(
                cam,
                segment->segment_id,
                bus,
                device,
                func,
                offset,
                in);
        if(res == 0) {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int
pci_segment_writel(
        struct pci_segment *segment,
        uint8_t bus,
        uint8_t device,
        uint8_t func,
        uint16_t offset,
        uint32_t in)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list) {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_writel(
                cam,
                segment->segment_id,
                bus,
                device,
                func,
                offset,
                in);
        if(res == 0) {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}
