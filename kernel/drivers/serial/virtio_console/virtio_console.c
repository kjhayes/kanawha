
#include <kanawha/init.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>

static int
virtio_console_probe(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    dprintk("virtio_console_probe\n");
    return 0;
}

static int
virtio_console_negotiate(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    return 0;
}

static int
virtio_console_init_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    return -EUNIMPL;
}

static int
virtio_console_deinit_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    return -EUNIMPL;
}

static struct virtio_driver_ops
virtio_console_driver_ops = {
    .probe = virtio_console_probe,
    .negotiate = virtio_console_negotiate,
    .init_device = virtio_console_init_device,
    .deinit_device = virtio_console_deinit_device,
};

static uint16_t
virtio_console_virtio_ids[] = {
    3,
};

static struct virtio_driver
virtio_console_driver = {
    .ops = &virtio_console_driver_ops,
    .num_ids = sizeof(virtio_console_virtio_ids) / sizeof(uint16_t),
    .ids = virtio_console_virtio_ids,
};

static int
register_virtio_console_driver(void)
{
    return register_virtio_driver(&virtio_console_driver);
}
declare_init_desc(device, register_virtio_console_driver, "Registered Virtio Console Driver");

