#ifndef __KANAWHA__VIRTIO_PCI_H__
#define __KANAWHA__VIRTIO_PCI_H__

#include <kanawha/endian.h>
#include <drivers/virtio/virtio.h>

struct virtio_pci_common_cfg
{
    /* About the whole device. */
    le32_t device_feature_select; /* read-write */
    le32_t device_feature; /* read-only for driver */
    le32_t driver_feature_select; /* read-write */
    le32_t driver_feature; /* read-write */
    le16_t config_msix_vector; /* read-write */
    le16_t num_queues; /* read-only for driver */
    uint8_t device_status; /* read-write */
    uint8_t config_generation; /* read-only for driver */

    /* About a specific virtqueue. */
    le16_t queue_select; /* read-write */
    le16_t queue_size; /* read-write */
    le16_t queue_msix_vector; /* read-write */
    le16_t queue_enable; /* read-write */
    le16_t queue_notify_off; /* read-only for driver */
    le64_t queue_desc; /* read-write */
    le64_t queue_driver; /* read-write */
    le64_t queue_device; /* read-write */
    le16_t queue_notify_data; /* read-only for driver */
    le16_t queue_reset; /* read-write */

} __attribute__((packed));

struct virtio_pci_device
{
    struct pci_func *func;
    struct virtio_device virtio_dev;

    ilist_node_t global_node;
};

extern struct virtio_transport virtio_pci_transport;

#endif
