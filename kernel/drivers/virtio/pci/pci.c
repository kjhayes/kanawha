
#include <drivers/virtio/pci.h>
#include <drivers/pci/pci.h>
#include <kanawha/init.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>

static DECLARE_SPINLOCK(virtio_pci_device_list_lock);
static DECLARE_ILIST(virtio_pci_device_list);

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
virtio_pci_transport_probe(
        struct pci_driver *driver,
        struct pci_func *func)
{
    printk("virtio-pci: Probed Device\n");
    return 0;
}

static int
virtio_pci_transport_init_device(
        struct pci_driver *driver,
        struct pci_func *func)
{
    printk("virtio-pci: Init Device\n");

    int res;

    struct virtio_pci_device *vpci_dev = kmalloc(sizeof(struct virtio_pci_device));
    if(vpci_dev == NULL) {
        return -ENOMEM;
    }
    memset(vpci_dev, 0, sizeof(struct virtio_pci_device));

    vpci_dev->func = func;
    vpci_dev->virtio_dev.transport = &virtio_pci_transport;
    vpci_dev->virtio_dev.virtio_id = virtio_pci_get_id(func);

    if(vpci_dev->virtio_dev.virtio_id == 0) {
        kfree(vpci_dev);
        return -EINVAL;
    }

    spin_lock(&virtio_pci_device_list_lock);

    res = register_virtio_device(&vpci_dev->virtio_dev);
    if(res) {
        spin_unlock(&virtio_pci_device_list_lock);
        kfree(vpci_dev);
        return res;
    }

    ilist_push_tail(&virtio_pci_device_list, &vpci_dev->global_node);

    spin_unlock(&virtio_pci_device_list_lock);

    return 0;
}

static int
virtio_pci_transport_deinit_device(
        struct pci_driver *driver,
        struct pci_func *func)
{
    printk("virtio-pci: Deinit Device\n");
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
virtio_pci_transport_driver_ops = {
    .probe = &virtio_pci_transport_probe,
    .init_device = &virtio_pci_transport_init_device,
    .deinit_device = &virtio_pci_transport_deinit_device,
};

static struct pci_driver 
virtio_pci_transport_driver = {
    .ops = &virtio_pci_transport_driver_ops,
    .num_ids = sizeof(virtio_pci_ids) / sizeof(struct pci_id),
    .ids = virtio_pci_ids,
};

static int
virtio_pci_transport_driver_register(void)
{
    return register_pci_driver(&virtio_pci_transport_driver);
}
declare_init(bus, virtio_pci_transport_driver_register);

