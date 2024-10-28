
#include <drivers/virtio/transport.h>
#include <drivers/virtio/pci.h>

static int
virtio_pci_reset(
        struct virtio_device *dev)
{
    printk("virtio_pci_reset\n");
    return -EUNIMPL;
}

static int
virtio_pci_set_status(
        struct virtio_device *dev,
        uint64_t to_set_mask)
{
    printk("virtio_pci_set_status\n");
    return -EUNIMPL;
}

static uint64_t
virtio_pci_read_status(
        struct virtio_device *dev)
{
    printk("virtio_pci_read_status\n");
    return VIRTIO_STATUS_DEVICE_NEEDS_RESET;
}

struct virtio_transport
virtio_pci_transport = {
    .reset = virtio_pci_reset,
    .set_status = virtio_pci_set_status,
    .read_status = virtio_pci_read_status,
};

