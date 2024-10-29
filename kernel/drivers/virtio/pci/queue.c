
#include <drivers/virtio/queue.h>
#include <drivers/virtio/pci.h>
#include <kanawha/stddef.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

struct virtio_pci_queue *
virtio_pci_create_queue(
        struct virtio_pci_device *device,
        uint16_t queue_no)
{
    int res;

    struct virtio_pci_queue *queue =
        kmalloc(sizeof(struct virtio_pci_queue));
    if(queue == NULL) {
        return NULL;
    }
    memset(queue, 0, sizeof(struct virtio_pci_queue));

    queue->queue.index = queue_no;
    queue->queue.ops = &virtio_pci_queue_ops;
    queue->queue.device = &device->virtio_dev;

    res = virtio_pci_device_set_queue_cfg(
            device,
            queue_no);
    if(res) {
        kfree(queue);
        return NULL;
    }

    queue->size = virtio_pci_device_queue_cfg_get_size(device);
    queue->msix_vector = virtio_pci_device_queue_cfg_get_msix(device);
    queue->notify_offset = virtio_pci_device_queue_cfg_get_notify_offset(device);

    return queue;
}

int
virtio_pci_destroy_queue(
        struct virtio_pci_device *device,
        struct virtio_pci_queue *queue)
{
    kfree(queue);
    return 0;
}

static int
virtio_pci_notify(
        struct virtio_queue *queue)
{
    struct virtio_pci_queue *pci_queue =
        container_of(queue, struct virtio_pci_queue, queue);
    struct virtio_device *vdev =
        queue->device;
    struct virtio_pci_device *vpci_dev =
        container_of(vdev, struct virtio_pci_device, virtio_dev);

    size_t offset = pci_queue->notify_offset * vpci_dev->notify_multiplier;

    // TODO: Handle VIRTIO_F_NOTIFICATION_DATA
    virtio_pci_cap_bar_writew(
            vpci_dev,
            vpci_dev->notify_cap,
            offset,
            virtio_queue_index(vdev, queue));

    return 0;
}

struct virtio_queue_ops
virtio_pci_queue_ops = {
    .notify = virtio_pci_notify,
};

