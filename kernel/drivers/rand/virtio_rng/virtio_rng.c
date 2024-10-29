
#include <kanawha/init.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>

static int
virtio_rng_probe(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    printk("virtio_rng_probe\n");
    return 0;
}

static int
virtio_rng_negotiate(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    printk("virtio_rng_negotiate\n");
    return 0;
}

static int
virtio_rng_init_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    printk("virtio_rng_init_device\n");
    return -EUNIMPL;
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

