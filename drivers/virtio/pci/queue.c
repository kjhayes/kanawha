
#include <drivers/virtio/queue.h>
#include <drivers/virtio/pci.h>
#include <drivers/virtio/request.h>
#include <kanawha/bitmap.h>
#include <kanawha/stddef.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <drivers/pci/irq.h>

#define VIRTIO_MSI_NO_VECTOR 0xffff

static int
virtio_pci_queue_used_notification_irq_handler(
        struct excp_state *excp_state,
        struct irq_action *action)
{
    int res;

    struct virtio_pci_queue *queue =
        action->handler_data.priv_data;

    dprintk("virtio_pci_queue: queue=%p, Queue(0x%lx) IRQ Handler!\n",
            &queue->queue,
            queue->queue.index);

    res = virtio_queue_handle_used_notification(&queue->queue);
    if(res) {
        eprintk("virtio_pci_queue_used_notification_irq_handler: Failed to handle used notification (err=%s)\n",
                errnostr(res));
    }

    return IRQ_NONE;
}


struct virtio_pci_queue *
virtio_pci_create_queue(
        struct virtio_pci_device *device,
        uint16_t queue_no)
{
    int res;

    struct virtio_pci_queue *queue =
        kzmalloc(sizeof(struct virtio_pci_queue), KM_KERNEL);
    if(queue == NULL) {
        return NULL;
    }

    res = virtio_pci_device_set_queue_cfg(
            device,
            queue_no);
    if(res) {
        kfree(queue);
        return NULL;
    }

    queue->notify_offset = virtio_pci_device_queue_cfg_get_notify_offset(device);
    queue->notify_data = virtio_pci_device_queue_cfg_get_notify_data(device);

    uint16_t queue_size = virtio_pci_device_queue_cfg_get_size(device);

    size_t max_num_irqs = pci_func_num_irqs(device->func);
    if(max_num_irqs == 0) {
        kfree(queue);
        eprintk("Cannot handle virtio queue without an interrupt method!\n");
        return NULL;
    }

    queue->msix_vector = queue_no % max_num_irqs;

    irq_t irq = pci_func_get_irq(
            device->func,
            queue->msix_vector);
    if(irq == NULL_IRQ) {
        kfree(queue);
        eprintk("Failed to get virtio queue IRQ!\n");
        return NULL;
    }

    virtio_pci_device_queue_cfg_set_msix(device, queue->msix_vector);
    uint16_t resp_vector = virtio_pci_device_queue_cfg_get_msix(device);
    if(resp_vector != queue->msix_vector) {
        eprintk("virtio_pci_queue: Queue rejected MSI-X vector 0x%lx (resp_vector=0x%lx)\n",
                (ul_t)queue->msix_vector,
                (ul_t)resp_vector);
        kfree(queue);
        return NULL;
    }

    dprintk("VIRTIO QUEUE: irq=0x%lx\n",
            irq);

    res = virtio_queue_init_struct(
            &queue->queue,
            &virtio_pci_queue_ops,
            &device->virtio_dev,
            queue_no,
            queue_size);
    if(res) {
        eprintk("virtio_pci_queue: Failed to initialize queue struct (err=%s)\n");
        kfree(queue);
        return NULL;
    }

    struct irq_desc *irq_desc = irq_to_desc(irq);
    queue->irq_action = irq_install_handler(
            irq_desc,
            (void*)queue,
            virtio_pci_queue_used_notification_irq_handler);
    if(queue->irq_action == NULL) {
        eprintk("virtio_pci_queue: Failed to install irq handler!\n");
        virtio_queue_deinit_struct(&queue->queue);
        kfree(queue);
        return NULL;
    }

    unmask_irq(irq);

    return queue;
}

int
virtio_pci_destroy_queue(
        struct virtio_pci_device *device,
        struct virtio_pci_queue *queue)
{
    int res;
    irq_uninstall_action(queue->irq_action);
    res = virtio_queue_deinit_struct(&queue->queue);
    if(res) {
        return res;
    }
    kfree(queue);
    return 0;
}

static int
virtio_pci_set_desc_table(
        struct virtio_queue *queue,
        void __phys *ptr)
{
    int res;

    struct virtio_pci_queue *pci_queue =
        container_of(queue, struct virtio_pci_queue, queue);
    struct virtio_device *vdev =
        queue->device;
    struct virtio_pci_device *vpci_dev =
        container_of(vdev, struct virtio_pci_device, virtio_dev);

    res = virtio_pci_device_set_queue_cfg(
            vpci_dev,
            queue->index);
    if(res) {
        return res;
    }

    virtio_pci_device_queue_cfg_set_desc(
            vpci_dev,
            (uint64_t)ptr);

    return 0;
}

static int
virtio_pci_set_avail_ring(
        struct virtio_queue *queue,
        void __phys *ptr)
{
    int res;

    struct virtio_pci_queue *pci_queue =
        container_of(queue, struct virtio_pci_queue, queue);
    struct virtio_device *vdev =
        queue->device;
    struct virtio_pci_device *vpci_dev =
        container_of(vdev, struct virtio_pci_device, virtio_dev);

    res = virtio_pci_device_set_queue_cfg(
            vpci_dev,
            queue->index);
    if(res) {
        return res;
    }

    virtio_pci_device_queue_cfg_set_driver_area(
            vpci_dev,
            (uint64_t)ptr);

    return 0;
}

static int
virtio_pci_set_used_ring(
        struct virtio_queue *queue,
        void __phys *ptr)
{
    int res;

    struct virtio_pci_queue *pci_queue =
        container_of(queue, struct virtio_pci_queue, queue);
    struct virtio_device *vdev =
        queue->device;
    struct virtio_pci_device *vpci_dev =
        container_of(vdev, struct virtio_pci_device, virtio_dev);

    res = virtio_pci_device_set_queue_cfg(
            vpci_dev,
            queue->index);
    if(res) {
        return res;
    }

    virtio_pci_device_queue_cfg_set_device_area(
            vpci_dev,
            (uint64_t)ptr);

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
    dprintk("virtio_pci_notify(queue=0x%x, notify_offset=0x%lx, notify_mult=0x%lx, offset=0x%lx, notify_cap_offset=%p, notify_cap_length=%p) index=0x%lx, data=0x%x\n",
            virtio_queue_index(vdev, queue),
            pci_queue->notify_offset,
            vpci_dev->notify_multiplier,
            offset,
            vpci_dev->notify_cap->offset,
            vpci_dev->notify_cap->length,
            queue->index,
            (uint32_t)pci_queue->notify_data
            );
    virtio_pci_cap_bar_writew(
            vpci_dev,
            vpci_dev->notify_cap,
            offset,
            queue->index);

    return 0;
}

static int
virtio_pci_enable_queue(
        struct virtio_queue *queue)
{
    int res;

    struct virtio_pci_queue *pci_queue =
        container_of(queue, struct virtio_pci_queue, queue);
    struct virtio_device *vdev =
        queue->device;
    struct virtio_pci_device *vpci_dev =
        container_of(vdev, struct virtio_pci_device, virtio_dev);

    res = virtio_pci_device_set_queue_cfg(
            vpci_dev,
            queue->index);
    if(res) {
        return res;
    }

    virtio_pci_device_queue_cfg_set_enabled(
            vpci_dev,
            (uint64_t)1);

    return 0;
}

static int
virtio_pci_disable_queue(
        struct virtio_queue *queue)
{
    int res;

    struct virtio_pci_queue *pci_queue =
        container_of(queue, struct virtio_pci_queue, queue);
    struct virtio_device *vdev =
        queue->device;
    struct virtio_pci_device *vpci_dev =
        container_of(vdev, struct virtio_pci_device, virtio_dev);

    res = virtio_pci_device_set_queue_cfg(
            vpci_dev,
            queue->index);
    if(res) {
        return res;
    }

    virtio_pci_device_queue_cfg_set_enabled(
            vpci_dev,
            (uint64_t)0);

    return 0;
}

struct virtio_queue_ops
virtio_pci_queue_ops = {
    .set_desc_table = virtio_pci_set_desc_table,
    .set_avail_ring = virtio_pci_set_avail_ring,
    .set_used_ring = virtio_pci_set_used_ring,
    .notify = virtio_pci_notify,
    .enable = virtio_pci_enable_queue,
    .disable = virtio_pci_enable_queue,
};

