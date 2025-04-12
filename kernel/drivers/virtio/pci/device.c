
#include <drivers/virtio/device.h>
#include <drivers/virtio/pci.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/kmalloc.h>

static int
virtio_pci_reset(
        struct virtio_device *dev)
{
    dprintk("virtio_pci_reset\n");

    struct virtio_pci_device *vdev =
        container_of(dev, struct virtio_pci_device, virtio_dev);

    virtio_pci_cap_bar_writeb(
            vdev,
            vdev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_DEVICE_STATUS,
            0x0);

    return 0;
}

static int
virtio_pci_set_status(
        struct virtio_device *dev,
        uint8_t to_set_mask)
{
    dprintk("virtio_pci_set_status\n");

    struct virtio_pci_device *vdev =
        container_of(dev, struct virtio_pci_device, virtio_dev);

    virtio_pci_cap_bar_writeb(
            vdev,
            vdev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_DEVICE_STATUS,
            to_set_mask);

    return 0;
}

static uint8_t
virtio_pci_read_status(
        struct virtio_device *dev)
{
    dprintk("virtio_pci_read_status\n");

    struct virtio_pci_device *vdev =
        container_of(dev, struct virtio_pci_device, virtio_dev);

    uint8_t status =
        virtio_pci_cap_bar_readb(
                vdev,
                vdev->common_cfg_cap,
                VIRTIO_PCI_COMMON_CFG_DEVICE_STATUS);

    return status;

}

static int
virtio_pci_check_feature(
        struct virtio_device *dev,
        size_t feat_bit)
{
    struct virtio_pci_device *vdev =
        container_of(dev, struct virtio_pci_device, virtio_dev);

    size_t long_index = feat_bit / 32;
    size_t bit_index = feat_bit % 32;

    virtio_pci_cap_bar_writel(
            vdev,
            vdev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_DEVICE_FEATURE_SELECT,
            long_index);

    uint32_t bits =
        virtio_pci_cap_bar_readl(
                vdev,
                vdev->common_cfg_cap,
                VIRTIO_PCI_COMMON_CFG_DEVICE_FEATURE);

    return !!(bits & (1ULL<<bit_index));
}

static int
virtio_pci_accept_feature(
        struct virtio_device *dev,
        size_t feat_bit)
{
    struct virtio_pci_device *vdev =
        container_of(dev, struct virtio_pci_device, virtio_dev);

    size_t long_index = feat_bit / 32;
    size_t bit_index = feat_bit % 32;

    dprintk("virtio_pci_accept_feature: bit=0x%lx, long_index=0x%lx, bit_index=0x%lx\n", feat_bit, long_index, bit_index);

    virtio_pci_cap_bar_writel(
            vdev,
            vdev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_DRIVER_FEATURE_SELECT,
            long_index);

    uint32_t bits =
        virtio_pci_cap_bar_readl(
                vdev,
                vdev->common_cfg_cap,
                VIRTIO_PCI_COMMON_CFG_DRIVER_FEATURE);

    bits |= (1ULL<<bit_index);

    virtio_pci_cap_bar_writel(
            vdev,
            vdev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_DRIVER_FEATURE,
            bits);

    return 0;
}

static int
virtio_pci_init_queues(
        struct virtio_device *vdev)
{
    int res;

    struct virtio_pci_device *vpci_dev =
        container_of(vdev, struct virtio_pci_device, virtio_dev);

    if(vdev->queues != NULL) {
        return -EINVAL;
    }

    vdev->num_queues = virtio_pci_cap_bar_readw(
            vpci_dev,
            vpci_dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_NUM_QUEUES);

    vdev->queues = kmalloc(sizeof(struct virtio_pci_queue*) * vdev->num_queues);
    if(vdev->queues == NULL) {
        return -ENOMEM;
    }
    memset(vdev->queues, 0, sizeof(struct virtio_pci_queue*) * vdev->num_queues);

    for(size_t i = 0; i < vdev->num_queues; i++) {
        struct virtio_pci_queue *vqueue =
            virtio_pci_create_queue(vpci_dev, i);
        if(vqueue == NULL) {
            vdev->queues[i] = NULL;
            wprintk("Failed to create virtio_pci_queue (index=0x%llx)\n",
                    i);
            continue;
        }
        vdev->queues[i] = &vqueue->queue;
    }

    dprintk("virtio_pci_init_queues: num_queues=0x%x\n",
            vdev->num_queues);
   
    return 0;
}

static int
virtio_pci_deinit_queues(
        struct virtio_device *vdev)
{
    struct virtio_pci_device *vpci_dev =
        container_of(vdev, struct virtio_pci_device, virtio_dev);

    if(vdev->queues != NULL) {
        for(uint16_t i = 0; i < vdev->num_queues; i++) {
            struct virtio_queue *vqueue = vdev->queues[i];
            if(vqueue == NULL) {
                continue;
            }

            struct virtio_pci_queue *vpci_queue =
                container_of(vqueue, struct virtio_pci_queue, queue);

            virtio_pci_destroy_queue(vpci_dev, vpci_queue);
        }
        kfree(vdev->queues);
    }

    return 0;
}

static int
virtio_pci_device_cfg_writeb(
        struct virtio_device *virtio_dev,
        size_t offset,
        uint8_t value)
{
    int res;
    struct virtio_pci_device *dev =
        container_of(virtio_dev, struct virtio_pci_device, virtio_dev);

    if(dev->device_cap == NULL) {
        return -ENXIO;
    }

    virtio_pci_cap_bar_writeb(
            dev,
            dev->device_cap,
            offset,
            value);

    return 0;
}
static int
virtio_pci_device_cfg_writew(
        struct virtio_device *virtio_dev,
        size_t offset,
        uint16_t value)
{
    int res;
    struct virtio_pci_device *dev =
        container_of(virtio_dev, struct virtio_pci_device, virtio_dev);

    if(dev->device_cap == NULL) {
        return -ENXIO;
    }

    virtio_pci_cap_bar_writew(
            dev,
            dev->device_cap,
            offset,
            value);

    return 0;
}
static int
virtio_pci_device_cfg_writel(
        struct virtio_device *virtio_dev,
        size_t offset,
        uint32_t value)
{
    int res;
    struct virtio_pci_device *dev =
        container_of(virtio_dev, struct virtio_pci_device, virtio_dev);

    if(dev->device_cap == NULL) {
        return -ENXIO;
    }

    virtio_pci_cap_bar_writel(
            dev,
            dev->device_cap,
            offset,
            value);

    return 0;
}
static int
virtio_pci_device_cfg_writeq(
        struct virtio_device *virtio_dev,
        size_t offset,
        uint64_t value)
{
    int res;
    struct virtio_pci_device *dev =
        container_of(virtio_dev, struct virtio_pci_device, virtio_dev);

    if(dev->device_cap == NULL) {
        return -ENXIO;
    }

    virtio_pci_cap_bar_writeq(
            dev,
            dev->device_cap,
            offset,
            value);

    return 0;
}

static int
virtio_pci_device_cfg_readb(
        struct virtio_device *virtio_dev,
        size_t offset,
        uint8_t *value)
{
    int res;
    struct virtio_pci_device *dev =
        container_of(virtio_dev, struct virtio_pci_device, virtio_dev);

    if(dev->device_cap == NULL) {
        return -ENXIO;
    }

    *value = virtio_pci_cap_bar_readb(
            dev,
            dev->device_cap,
            offset);

    return 0;
}
static int
virtio_pci_device_cfg_readw(
        struct virtio_device *virtio_dev,
        size_t offset,
        uint16_t *value)
{
    int res;
    struct virtio_pci_device *dev =
        container_of(virtio_dev, struct virtio_pci_device, virtio_dev);

    if(dev->device_cap == NULL) {
        return -ENXIO;
    }

    *value = virtio_pci_cap_bar_readw(
            dev,
            dev->device_cap,
            offset);

    return 0;
}
static int
virtio_pci_device_cfg_readl(
        struct virtio_device *virtio_dev,
        size_t offset,
        uint32_t *value)
{
    int res;
    struct virtio_pci_device *dev =
        container_of(virtio_dev, struct virtio_pci_device, virtio_dev);

    if(dev->device_cap == NULL) {
        return -ENXIO;
    }

    *value = virtio_pci_cap_bar_readl(
            dev,
            dev->device_cap,
            offset);

    return 0;
}
static int
virtio_pci_device_cfg_readq(
        struct virtio_device *virtio_dev,
        size_t offset,
        uint64_t *value)
{
    int res;
    struct virtio_pci_device *dev =
        container_of(virtio_dev, struct virtio_pci_device, virtio_dev);

    if(dev->device_cap == NULL) {
        return -ENXIO;
    }

    *value = virtio_pci_cap_bar_readq(
            dev,
            dev->device_cap,
            offset);

    return 0;
}

struct virtio_device_ops
virtio_pci_device_ops = {
    .reset = virtio_pci_reset,
    .set_status = virtio_pci_set_status,
    .read_status = virtio_pci_read_status,
    .check_feature = virtio_pci_check_feature,
    .accept_feature = virtio_pci_accept_feature,
    .init_queues = virtio_pci_init_queues,
    .deinit_queues = virtio_pci_deinit_queues,

    // Write Device Specific Config
    .cfg_writeb = virtio_pci_device_cfg_writeb,
    .cfg_writew = virtio_pci_device_cfg_writew,
    .cfg_writel = virtio_pci_device_cfg_writel,
    .cfg_writeq = virtio_pci_device_cfg_writeq,
    // Read Device Specific Config
    .cfg_readb = virtio_pci_device_cfg_readb,
    .cfg_readw = virtio_pci_device_cfg_readw,
    .cfg_readl = virtio_pci_device_cfg_readl,
    .cfg_readq = virtio_pci_device_cfg_readq,
};

