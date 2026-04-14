
#include <drivers/pci/cfg.h>
#include <drivers/pci/pci.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/rwlock.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>

DEFINE_LOCAL_THREAD_LOCK(pci_segment_tree_lock);
static DECLARE_PTREE(pci_segment_tree);

static DECLARE_RLOCK(pci_cam_list_lock);
static DECLARE_ILIST(pci_cam_list);

int
register_pci_cam(struct pci_cam *cam, unsigned long flags)
{
    cam->flags = flags;
    rlock_write_lock(&pci_cam_list_lock);

    ilist_push_tail(&pci_cam_list, &cam->global_node);

    rlock_write_unlock(&pci_cam_list_lock);
    return 0;
}

struct pci_segment *
pci_segment_create_or_get(uint16_t segment_id)
{
    int res;

    struct pci_segment *segment = NULL;

    // Find the segment if it already exists, or create a new structure for it
    pci_segment_tree_lock_acquire();
    struct ptree_node *node;
    node = ptree_get(&pci_segment_tree, segment_id);
    if(node != NULL) {
        segment = container_of(node, struct pci_segment, global_node);
    }

    // The segment does not already exist, create it
    if(segment == NULL)
    {
        printk("Registering PCI Segment %lu\n", segment_id);

        segment = kmalloc(sizeof(struct pci_segment), KM_KERNEL);
        if(segment == NULL)
        {
            eprintk("Ran out of memory when allocating PCI segment "
                    "struct!\n");
            pci_segment_tree_lock_release();
            return NULL;
        }
        ptree_init(&segment->bus_tree);

        segment->segment_id = segment_id;

        res = mem_flags_init(&segment->mmio_flags,
                       0,
                       0x1000,
                       NULL);
        if(res) {
            pci_segment_tree_lock_release();
            kfree(segment);
            return NULL;
        }
        
        // Mark low 32-bit BAR(s)
        mem_flags_set_flags(
                &segment->mmio_flags,
                0x0,
                0xFFFFFFFF,
                PCI_MMIO_MEM_32_BIT);

        res = mem_flags_init(&segment->pio_flags,
                       0,
                       0x1000,
                       NULL);
        if(res) {
            pci_segment_tree_lock_release();
            mem_flags_deinit(&segment->mmio_flags);
            kfree(segment);
            return NULL;
        }

        ptree_insert(&pci_segment_tree, &segment->global_node, segment_id);
    }
    pci_segment_tree_lock_release();

    return segment;
}

int
pci_segment_probe(struct pci_segment *segment,
                  size_t assumed_bus_start,
                  size_t assumed_bus_count)
{
    int res;
    for(size_t bus_index = 0; bus_index < assumed_bus_count; bus_index++)
    {
        size_t bus = assumed_bus_start + bus_index;

        res = pci_probe_bus(segment, bus);
        if(res)
        {
            wprintk("Failed to probe PCI bus %lu! (err=%s)\n",
                    (ul_t)bus,
                    errnostr(res));
        }
    }
    return 0;
}

int
pci_segment_readb(struct pci_segment *segment,
                  uint8_t bus,
                  uint8_t device,
                  uint8_t func,
                  uint16_t offset,
                  uint8_t *out)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list)
    {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_readb(cam,
                            segment->segment_id,
                            bus,
                            device,
                            func,
                            offset,
                            out);
        if(res == 0)
        {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int
pci_segment_readw(struct pci_segment *segment,
                  uint8_t bus,
                  uint8_t device,
                  uint8_t func,
                  uint16_t offset,
                  uint16_t *out)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list)
    {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_readw(cam,
                            segment->segment_id,
                            bus,
                            device,
                            func,
                            offset,
                            out);
        if(res == 0)
        {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int
pci_segment_readl(struct pci_segment *segment,
                  uint8_t bus,
                  uint8_t device,
                  uint8_t func,
                  uint16_t offset,
                  uint32_t *out)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list)
    {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_readl(cam,
                            segment->segment_id,
                            bus,
                            device,
                            func,
                            offset,
                            out);
        if(res == 0)
        {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int
pci_segment_writeb(struct pci_segment *segment,
                   uint8_t bus,
                   uint8_t device,
                   uint8_t func,
                   uint16_t offset,
                   uint8_t in)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list)
    {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_writeb(cam,
                             segment->segment_id,
                             bus,
                             device,
                             func,
                             offset,
                             in);
        if(res == 0)
        {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int
pci_segment_writew(struct pci_segment *segment,
                   uint8_t bus,
                   uint8_t device,
                   uint8_t func,
                   uint16_t offset,
                   uint16_t in)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list)
    {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_writew(cam,
                             segment->segment_id,
                             bus,
                             device,
                             func,
                             offset,
                             in);
        if(res == 0)
        {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int
pci_segment_writel(struct pci_segment *segment,
                   uint8_t bus,
                   uint8_t device,
                   uint8_t func,
                   uint16_t offset,
                   uint32_t in)
{
    int res;

    rlock_read_lock(&pci_cam_list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &pci_cam_list)
    {
        struct pci_cam *cam = container_of(node, struct pci_cam, global_node);
        res = pci_cam_writel(cam,
                             segment->segment_id,
                             bus,
                             device,
                             func,
                             offset,
                             in);
        if(res == 0)
        {
            rlock_read_unlock(&pci_cam_list_lock);
            return 0;
        }
    }

    rlock_read_unlock(&pci_cam_list_lock);

    return -EINVAL;
}

int pci_for_each_segment(int(*callback)(struct pci_segment *segment))
{
    int res;
    pci_segment_tree_lock_acquire();
    struct ptree_node *pnode = ptree_get_first(&pci_segment_tree);
    while(pnode) {
        struct pci_segment *segment =
            container_of(pnode, struct pci_segment, global_node);
        res = (*callback)(segment);
        if(res) {
            pci_segment_tree_lock_release();
            return res;
        }
        pnode = ptree_get_next(pnode);
    }
    pci_segment_tree_lock_release();
    return 0;

}

int
pci_for_each_func(int(*callback)(struct pci_func *func))
{
    int res;
    pci_segment_tree_lock_acquire();
    struct ptree_node *pnode = ptree_get_first(&pci_segment_tree);
    while(pnode) {
        struct pci_segment *segment =
            container_of(pnode, struct pci_segment, global_node);
        res = pci_segment_for_each_func(
                segment,
                callback);
        if(res) {
            pci_segment_tree_lock_release();
            return res;
        }
        pnode = ptree_get_next(pnode);
    }
    pci_segment_tree_lock_release();
    return 0;
}

int
pci_segment_for_each_func(
        struct pci_segment *segment,
        int(*callback)(struct pci_func *func))
{
    int res;
    struct ptree_node *pnode = ptree_get_first(&segment->bus_tree);
    while(pnode) {
        struct pci_bus *bus =
            container_of(pnode, struct pci_bus, segment_node);
        res = pci_bus_for_each_func(
                bus,
                callback);
        if(res) {
            return res;
        }
        pnode = ptree_get_next(pnode);
    }
    return 0;
}

int
pci_bus_for_each_func(
        struct pci_bus *bus,
        int(*callback)(struct pci_func *func))
{
    int res;
    struct ptree_node *pnode = ptree_get_first(&bus->device_tree);
    while(pnode) {
        struct pci_device *device =
            container_of(pnode, struct pci_device, bus_node);
        res = pci_device_for_each_func(
                device,
                callback);
        if(res) {
            return res;
        }
        pnode = ptree_get_next(pnode);
    }
    return 0;
}

int
pci_device_for_each_func(
        struct pci_device *device,
        int(*callback)(struct pci_func *func))
{
    int res;
    struct ptree_node *pnode = ptree_get_first(&device->function_tree);
    while(pnode) {
        struct pci_func *func =
            container_of(pnode, struct pci_func, device_node);
        res = (*callback)(func);
        if(res) {
            return res;
        }
        pnode = ptree_get_next(pnode);
    }
    return 0;
}

static void
mmio_mem_flags_printer(printk_f *printer, unsigned long flags)
{
    (*printer)("%s%s%s%s%s",
            flags & PCI_MMIO_MEM_MAPPED ? "[MAPPED]" : "",
            flags & PCI_MMIO_MEM_32_BIT ? "[32]" : "",
            flags & PCI_MMIO_MEM_SNOOPED ? "[SNOOPED]" : "",
            flags & PCI_MMIO_MEM_PREFETCH ? "[PREFETCH]" : "",
            flags & PCI_MMIO_MEM_CONFIG ? "[CONFIG]" : ""
            );
}
int
pci_segment_dump_mmio_mem_flags(
        struct pci_segment *segment,
        printk_f *printer)
{
    mem_flags_print(
            &segment->mmio_flags,
            printer,
            mmio_mem_flags_printer);
    return 0;
}

static void
pio_mem_flags_printer(printk_f *printer, unsigned long flags)
{
    (*printer)("%s%s",
            flags & PCI_PIO_MEM_MAPPED ? "[MAPPED]" : "",
            flags & PCI_PIO_MEM_SNOOPED ? "[SNOOPED]" : ""
            );
}
int
pci_segment_dump_pio_mem_flags(
        struct pci_segment *segment,
        printk_f *printer)
{
    mem_flags_print(
            &segment->pio_flags,
            printer,
            pio_mem_flags_printer);

    return 0;
}

