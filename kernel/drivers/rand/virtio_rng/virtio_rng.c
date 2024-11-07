
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>

#define VIRTIO_RNG_BUFSIZE 0x1000

struct virtio_rng_device {
    struct virtio_queue *request_queue;

    size_t bufsize;
    dma_addr_t buffer;
};

static int
virtio_rng_probe(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    dprintk("virtio_rng_probe\n");
    return 0;
}

static int
virtio_rng_negotiate(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    dprintk("virtio_rng_negotiate\n");
    return 0;
}

static int
virtio_rng_init_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;

    printk("virtio_rng_init_device\n");

    if(device->num_queues != 1) {
        return -EINVAL;
    }

    struct virtio_rng_device *rng = kmalloc(sizeof(struct virtio_rng_device));
    if(rng == NULL) {
        return -ENOMEM;
    }
    memset(rng, 0, sizeof(struct virtio_rng_device));

    rng->request_queue = device->queues[0];
    if(rng->request_queue == NULL) {
        kfree(rng);
        return -EINVAL;
    }

    rng->bufsize = VIRTIO_RNG_BUFSIZE;
    res = dma_alloc(
            rng->bufsize,
            0,
            DMA_PHYS_64,
            &rng->buffer);
    if(res) {
        kfree(rng);
        return res;
    }

    printk("virtio_rng Initialized\n");

    return 0;
}

static int
virtio_rng_deinit_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    return -EUNIMPL;
}

static struct virtio_driver_ops
virtio_rng_driver_ops = {
    .probe = virtio_rng_probe,
    .negotiate = virtio_rng_negotiate,
    .init_device = virtio_rng_init_device,
    .deinit_device = virtio_rng_deinit_device,
};

static uint16_t
virtio_rng_virtio_ids[] = {
    4,
};

static struct virtio_driver
virtio_rng_driver = {
    .ops = &virtio_rng_driver_ops,
    .num_ids = sizeof(virtio_rng_virtio_ids) / sizeof(uint16_t),
    .ids = virtio_rng_virtio_ids,
};

static int
register_virtio_rng_driver(void)
{
    return register_virtio_driver(&virtio_rng_driver);
}
declare_init_desc(device, register_virtio_rng_driver, "Registered Virtio RNG Driver");

