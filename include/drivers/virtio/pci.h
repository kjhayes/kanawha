#ifndef __KANAWHA__VIRTIO_PCI_H__
#define __KANAWHA__VIRTIO_PCI_H__

#include <kanawha/endian.h>
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/device.h>
#include <drivers/virtio/queue.h>
#include <drivers/pci/pci.h>
#include <drivers/pci/cap.h>
#include <drivers/pci/bar.h>


#define VIRTIO_PCI_COMMON_CFG_DEVICE_FEATURE_SELECT 0x00
#define VIRTIO_PCI_COMMON_CFG_DEVICE_FEATURE        0x04
#define VIRTIO_PCI_COMMON_CFG_DRIVER_FEATURE_SELECT 0x08
#define VIRTIO_PCI_COMMON_CFG_DRIVER_FEATURE        0x0C
#define VIRTIO_PCI_COMMON_CFG_CONFIG_MSIX_VECTOR    0x10
#define VIRTIO_PCI_COMMON_CFG_NUM_QUEUES            0x12
#define VIRTIO_PCI_COMMON_CFG_DEVICE_STATUS         0x14
#define VIRTIO_PCI_COMMON_CFG_CONFIG_GENERATION     0x15
#define VIRTIO_PCI_COMMON_CFG_QUEUE_SELECT          0x16
#define VIRTIO_PCI_COMMON_CFG_QUEUE_SIZE            0x18
#define VIRTIO_PCI_COMMON_CFG_QUEUE_MSIX_VECTOR     0x1A
#define VIRTIO_PCI_COMMON_CFG_QUEUE_ENABLE          0x1C
#define VIRTIO_PCI_COMMON_CFG_QUEUE_NOTIFY_OFF      0x1E
#define VIRTIO_PCI_COMMON_CFG_QUEUE_DESC            0x20
#define VIRTIO_PCI_COMMON_CFG_QUEUE_DRIVER          0x28
#define VIRTIO_PCI_COMMON_CFG_QUEUE_DEVICE          0x30
#define VIRTIO_PCI_COMMON_CFG_QUEUE_NOTIFY_DATA     0x38
#define VIRTIO_PCI_COMMON_CFG_QUEUE_RESET           0x3A

struct virtio_pci_cap
{
    ilist_node_t list_node;

    struct pci_cap *cap;

    struct pci_bar *bar;
    size_t offset;
    size_t length;

    uint8_t cap_len;
    uint8_t type;
    uint8_t id;
};

struct virtio_pci_device
{
    struct pci_func *func;
    struct virtio_device virtio_dev;

    struct virtio_pci_cap *common_cfg_cap;
    struct virtio_pci_cap *notify_cap;
    uint16_t notify_multiplier;

    ilist_t cap_list;

    ilist_node_t global_node;
};

struct virtio_pci_queue {
    struct virtio_queue queue;

    uint16_t size;
    uint16_t msix_vector;
    uint16_t notify_offset;
};

extern struct virtio_device_ops virtio_pci_device_ops;
extern struct virtio_queue_ops virtio_pci_queue_ops;

static inline uint8_t
virtio_pci_cap_ext_cfg_readb(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint16_t offset)
{
    DEBUG_ASSERT(offset < cap->cap_len);
    return pci_cap_readb(
            dev->func,
            cap->cap,
            offset + 0x10);
}

static inline uint16_t
virtio_pci_cap_ext_cfg_readw(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint16_t offset)
{
    DEBUG_ASSERT(offset < cap->cap_len);
    return pci_cap_readw(
            dev->func,
            cap->cap,
            offset + 0x10);
}

static inline uint32_t
virtio_pci_cap_ext_cfg_readl(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint16_t offset)
{
    DEBUG_ASSERT(offset < cap->cap_len);
    return pci_cap_readl(
            dev->func,
            cap->cap,
            offset + 0x10);
}

static inline uint8_t
virtio_pci_cap_bar_readb(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint32_t offset)
{
    DEBUG_ASSERT(offset < cap->length);
    dprintk("virtio_pci_cap_bar_readb(offset=0x%lx, cap->offset=0x%lx)\n",
            offset, cap->offset);
    return pci_bar_readb(
            cap->bar,
            offset + cap->offset);
}

static inline uint16_t
virtio_pci_cap_bar_readw(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint32_t offset)
{
    DEBUG_ASSERT(offset < cap->length);
    return pci_bar_readw(
            cap->bar,
            offset + cap->offset);
}

static inline uint32_t
virtio_pci_cap_bar_readl(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint32_t offset)
{
    DEBUG_ASSERT(offset < cap->length);
    return pci_bar_readl(
            cap->bar,
            offset + cap->offset);
}

static inline uint64_t
virtio_pci_cap_bar_readq(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint32_t offset)
{
    DEBUG_ASSERT(offset < cap->length);
    return pci_bar_readq(
            cap->bar,
            offset + cap->offset);
}

static inline void 
virtio_pci_cap_bar_writeb(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint32_t offset,
        uint8_t val)
{
    DEBUG_ASSERT(offset < cap->length);
    return pci_bar_writeb(
            cap->bar,
            offset + cap->offset,
            val);
}

static inline void 
virtio_pci_cap_bar_writew(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint32_t offset,
        uint16_t val)
{
    DEBUG_ASSERT(offset < cap->length);
    return pci_bar_writew(
            cap->bar,
            offset + cap->offset,
            val);
}

static inline void 
virtio_pci_cap_bar_writel(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint32_t offset,
        uint32_t val)
{
    DEBUG_ASSERT(offset < cap->length);
    return pci_bar_writel(
            cap->bar,
            offset + cap->offset,
            val);
}

static inline void 
virtio_pci_cap_bar_writeq(
        struct virtio_pci_device *dev,
        struct virtio_pci_cap *cap,
        uint32_t offset,
        uint64_t val)
{
    DEBUG_ASSERT(offset < cap->length);
    return pci_bar_writeq(
            cap->bar,
            offset + cap->offset,
            val);
}

// Get/Set Which Queue's Config is Active
static inline uint16_t
virtio_pci_device_get_queue_cfg(
        struct virtio_pci_device *dev)
{
    return virtio_pci_cap_bar_readw(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_SELECT);
}
static inline int
virtio_pci_device_set_queue_cfg(
        struct virtio_pci_device *dev,
        uint16_t queue_no)
{
    virtio_pci_cap_bar_writew(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_SELECT,
            queue_no);
    return 0;
}

// Queue Size
static inline uint16_t
virtio_pci_device_queue_cfg_get_size(
        struct virtio_pci_device *dev)
{
    return virtio_pci_cap_bar_readw(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_SIZE);
}
static inline void 
virtio_pci_device_queue_cfg_set_size(
        struct virtio_pci_device *dev,
        uint16_t value)
{
    virtio_pci_cap_bar_writew(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_SIZE,
            value);
}

// Queue MSI-X
static inline uint16_t
virtio_pci_device_queue_cfg_get_msix(
        struct virtio_pci_device *dev)
{
    return virtio_pci_cap_bar_readw(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_MSIX_VECTOR);
}
static inline void 
virtio_pci_device_queue_cfg_set_msix(
        struct virtio_pci_device *dev,
        uint16_t value)
{
    virtio_pci_cap_bar_writew(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_MSIX_VECTOR,
            value);
}

// Queue MSI-X
static inline uint16_t
virtio_pci_device_queue_cfg_get_enabled(
        struct virtio_pci_device *dev)
{
    return virtio_pci_cap_bar_readw(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_ENABLE);
}
static inline void 
virtio_pci_device_queue_cfg_set_enabled(
        struct virtio_pci_device *dev,
        uint16_t value)
{
    virtio_pci_cap_bar_writew(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_ENABLE,
            value);
}

// Queue Notify Offset
static inline uint16_t
virtio_pci_device_queue_cfg_get_notify_offset(
        struct virtio_pci_device *dev)
{
    return virtio_pci_cap_bar_readw(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_NOTIFY_OFF);
}

// Queue Notify Data
static inline uint16_t
virtio_pci_device_queue_cfg_get_notify_data(
        struct virtio_pci_device *dev)
{
    return virtio_pci_cap_bar_readw(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_NOTIFY_DATA);
}

// Queue Reset
static inline uint16_t
virtio_pci_device_queue_cfg_get_reset(
        struct virtio_pci_device *dev)
{
    return virtio_pci_cap_bar_readw(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_RESET);
}
static inline void
virtio_pci_device_queue_cfg_set_reset(
        struct virtio_pci_device *dev,
        uint16_t value)
{
    virtio_pci_cap_bar_writew(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_RESET,
            value);
}

// Queue Descriptor Physical Address
static inline uint64_t
virtio_pci_device_queue_cfg_get_desc(
        struct virtio_pci_device *dev)
{
    return virtio_pci_cap_bar_readq(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_DESC);
}
static inline void 
virtio_pci_device_queue_cfg_set_desc(
        struct virtio_pci_device *dev,
        uint64_t value)
{
    virtio_pci_cap_bar_writeq(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_ENABLE,
            value);
}

// Queue Device Area Physical Address
static inline uint64_t
virtio_pci_device_queue_cfg_get_device_area(
        struct virtio_pci_device *dev)
{
    return virtio_pci_cap_bar_readq(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_DEVICE);
}
static inline void 
virtio_pci_device_queue_cfg_set_device_area(
        struct virtio_pci_device *dev,
        uint64_t value)
{
    virtio_pci_cap_bar_writeq(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_DEVICE,
            value);
}

// Queue Driver Area Physical Address
static inline uint64_t
virtio_pci_device_queue_cfg_get_driver_area(
        struct virtio_pci_device *dev)
{
    return virtio_pci_cap_bar_readq(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_DRIVER);
}
static inline void 
virtio_pci_device_queue_cfg_set_driver_area(
        struct virtio_pci_device *dev,
        uint64_t value)
{
    virtio_pci_cap_bar_writeq(
            dev,
            dev->common_cfg_cap,
            VIRTIO_PCI_COMMON_CFG_QUEUE_DRIVER,
            value);
}

// Virt-Queue Creation/Destruction
struct virtio_pci_queue *
virtio_pci_create_queue(
        struct virtio_pci_device *device,
        uint16_t queue_no);
int
virtio_pci_destroy_queue(
        struct virtio_pci_device *device,
        struct virtio_pci_queue *queue);

#endif
