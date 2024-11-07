
#include <drivers/virtio/pci.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/cap.h>
#include <kanawha/init.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>
#include <drivers/pci/irq.h>

static DECLARE_SPINLOCK(virtio_pci_device_list_lock);
static DECLARE_ILIST(virtio_pci_device_list);

#define VIRTIO_PCI_CAP_COMMON_CFG        0x1
#define VIRTIO_PCI_CAP_NOTIFY_CFG        0x2
#define VIRTIO_PCI_CAP_ISR_CFG           0x3
#define VIRTIO_PCI_CAP_DEVICE_CFG        0x4
#define VIRTIO_PCI_CAP_PCI_CFG           0x5
#define VIRTIO_PCI_CAP_SHARED_MEMORY_CFG 0x8
#define VIRTIO_PCI_CAP_VENDOR_CFG        0x9

static inline uint16_t
virtio_pci_get_id(struct pci_func *func)
{
    if(func->device_id >= 0x1040 && func->device_id < 0x1080) {
        return (func->device_id - 0x1040) + 1;
    }
    switch(func->device_id) {
        case 0x1000: // network
            return 1;
        case 0x1001: // block
            return 2;
        case 0x1002: // balloon
            return 5;
        case 0x1003: // console
            return 3;
        case 0x1004: // scsi
            return 8;
        case 0x1005: // entropy
            return 4;
        case 0x1009: // 9P
            return 9;
    }

    return 0;
}

static int
virtio_pci_deinit_capabilities(
        struct virtio_pci_device *vpci_dev)
{
    do
    {
        ilist_node_t *node = ilist_pop_head(&vpci_dev->cap_list);
        if(node == NULL) {
            break;
        }
        struct virtio_pci_cap *cap =
            container_of(node, struct virtio_pci_cap, list_node);

        kfree(cap);

    } while(1);
    return 0;
}

static int
virtio_pci_init_capabilities(
        struct virtio_pci_device *vpci_dev)
{
    int res = 0;

    ilist_init(&vpci_dev->cap_list);

    struct pci_func *func = vpci_dev->func;

    size_t num_found = 0;

    struct pci_cap *cap = pci_func_find_cap(
            vpci_dev->func,
            PCI_CAP_ID_VENDOR_SPECIFIC);

    while(cap != NULL)
    {
        num_found++;

        dprintk("before vcap_kmalloc\n");
        struct virtio_pci_cap *vcap =
            kmalloc(sizeof(struct virtio_pci_cap));
        dprintk("after vcap_kmalloc\n");
        if(vcap == NULL) {
            res = -ENOMEM;
            break;
        }
        memset(vcap, 0, sizeof(struct virtio_pci_cap));

        vcap->cap = cap;
        vcap->cap_len =     pci_cap_readb(func, cap, 0x2);
        vcap->type =        pci_cap_readb(func, cap, 0x3);
        uint8_t bar_index = pci_cap_readb(func, cap, 0x4);
        vcap->id =          pci_cap_readb(func, cap, 0x5);
        vcap->offset =      pci_cap_readl(func, cap, 0x8);
        vcap->length =      pci_cap_readl(func, cap, 0xC);

        dprintk("vcap->bar=0x%x, offset=0x%lx, length=0x%lx, type=0x%x\n",
                (uint32_t)bar_index, (uint32_t)vcap->offset, (uint32_t)vcap->length, (uint32_t)vcap->type);

        vcap->bar = &func->bars[bar_index];

        ilist_push_tail(&vpci_dev->cap_list, &vcap->list_node);

        cap = pci_func_find_next_cap(
                vpci_dev->func,
                cap,
                PCI_CAP_ID_VENDOR_SPECIFIC);
    }

    if(res) {
        eprintk("Failed to initialize virtio_pci capabilities (err=%s)\n",
                errnostr(res));
        virtio_pci_deinit_capabilities(vpci_dev);
        return res;
    }
    
    return 0;
}

static struct virtio_pci_cap *
virtio_pci_find_cap(
        struct virtio_pci_device *device,
        uint8_t type)
{
    ilist_node_t *node;
    ilist_for_each(node, &device->cap_list) {
        struct virtio_pci_cap *vcap =
            container_of(node, struct virtio_pci_cap, list_node);
        if(vcap->type == type) {
            return vcap;
        }
    }
    return NULL;
}

static int
virtio_pci_init_queues(
        struct virtio_pci_device *device)
{
    uint32_t num_queues =
        virtio_pci_cap_bar_readl(
                device,
                device->common_cfg_cap,
                VIRTIO_PCI_COMMON_CFG_NUM_QUEUES);
    dprintk("num_queues=0x%lx\n",
            num_queues);
    return 0;
}

static int
virtio_pci_deinit_queues(
        struct virtio_pci_device *device)
{
    return -EUNIMPL;
}

static int
virtio_pci_probe(
        struct pci_driver *driver,
        struct pci_func *func)
{
    dprintk("virtio-pci: Probed Device\n");
    return 0;
}

static int
virtio_pci_init_device(
        struct pci_driver *driver,
        struct pci_func *func)
{
    dprintk("virtio-pci: Init Device\n");

    int res;

    res = pci_func_start_irqs(func);
    if(res) {
        eprintk("Failed to start IRQ's on virtio-pci device! (err=%s)\n",
                errnostr(res));
        return res;
    }

    DEBUG_ASSERT(KERNEL_ADDR(func->irq_domain));

    struct virtio_pci_device *vpci_dev = kmalloc(sizeof(struct virtio_pci_device));
    if(vpci_dev == NULL) {
        return -ENOMEM;
    }
    memset(vpci_dev, 0, sizeof(struct virtio_pci_device));

    vpci_dev->func = func;
    vpci_dev->virtio_dev.ops = &virtio_pci_device_ops;
    vpci_dev->virtio_dev.virtio_id = virtio_pci_get_id(func);

    if(vpci_dev->virtio_dev.virtio_id == 0) {
        kfree(vpci_dev);
        return -EINVAL;
    }

    res = virtio_pci_init_capabilities(vpci_dev);
    if(res) {
        return res;
    }

    dprintk("virito_pci: finding common_cfg_cap\n");
    vpci_dev->common_cfg_cap =
        virtio_pci_find_cap(vpci_dev, VIRTIO_PCI_CAP_COMMON_CFG);
    if(vpci_dev->common_cfg_cap == NULL) {
        virtio_pci_deinit_capabilities(vpci_dev);
        kfree(vpci_dev);
        return -EINVAL;
    }

    dprintk("virito_pci: finding notify_cap\n");
    vpci_dev->notify_cap =
        virtio_pci_find_cap(vpci_dev, VIRTIO_PCI_CAP_NOTIFY_CFG);
    if(vpci_dev->notify_cap == NULL) {
        eprintk("virtio_pci: Could not find VIRTIO_PCI_CAP_NOTIFY_CFG!\n");
        virtio_pci_deinit_capabilities(vpci_dev);
        kfree(vpci_dev);
        return -EINVAL;
    }

    vpci_dev->notify_multiplier = virtio_pci_cap_ext_cfg_readl(
            vpci_dev, vpci_dev->notify_cap, 0);

    spin_lock(&virtio_pci_device_list_lock);

    dprintk("virito_pci: registering virito_device\n");
    res = register_virtio_device(&vpci_dev->virtio_dev);
    if(res) {
        spin_unlock(&virtio_pci_device_list_lock);
        virtio_pci_deinit_capabilities(vpci_dev);
        kfree(vpci_dev);
        return res;
    }

    ilist_push_tail(&virtio_pci_device_list, &vpci_dev->global_node);

    spin_unlock(&virtio_pci_device_list_lock);

    return 0;
}

static int
virtio_pci_deinit_device(
        struct pci_driver *driver,
        struct pci_func *func)
{
    dprintk("virtio-pci: Deinit Device\n");
    return -EUNIMPL;
}

static struct pci_id
virtio_pci_ids[] = {
    // Transitional Device ID's
    { .vendor = 0x1AF4, .device = 0x1000, },
    { .vendor = 0x1AF4, .device = 0x1001, },
    { .vendor = 0x1AF4, .device = 0x1002, },
    { .vendor = 0x1AF4, .device = 0x1003, },
    { .vendor = 0x1AF4, .device = 0x1004, },
    { .vendor = 0x1AF4, .device = 0x1005, },
    { .vendor = 0x1AF4, .device = 0x1009, },
    // Non-Transitional Device ID's
    { .vendor = 0x1AF4, .device = 0x1040 + 0x00, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x01, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x02, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x03, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x04, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x05, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x06, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x07, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x08, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x09, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x0A, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x0B, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x0C, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x0D, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x0E, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x0F, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x10, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x11, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x12, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x13, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x14, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x15, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x16, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x17, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x18, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x19, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x1A, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x1B, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x1C, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x1D, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x1E, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x1F, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x20, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x21, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x22, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x23, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x24, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x25, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x26, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x27, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x28, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x29, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x2A, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x2B, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x2C, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x2D, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x2E, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x2F, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x30, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x31, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x32, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x33, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x34, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x35, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x36, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x37, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x38, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x39, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x3A, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x3B, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x3C, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x3D, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x3E, },
    { .vendor = 0x1AF4, .device = 0x1040 + 0x3F, },
};

static struct pci_driver_ops
virtio_pci_driver_ops = {
    .probe = &virtio_pci_probe,
    .init_device = &virtio_pci_init_device,
    .deinit_device = &virtio_pci_deinit_device,
};

static struct pci_driver 
virtio_pci_driver = {
    .ops = &virtio_pci_driver_ops,
    .num_ids = sizeof(virtio_pci_ids) / sizeof(struct pci_id),
    .ids = virtio_pci_ids,
};

static int
virtio_pci_driver_register(void)
{
    return register_pci_driver(&virtio_pci_driver);
}
declare_init_desc(bus, virtio_pci_driver_register, "Registering Virtio PCI Transport");

