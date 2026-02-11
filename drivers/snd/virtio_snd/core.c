
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/irq.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>
#include <kanawha/endian.h>

struct virtio_snd_config {
    le32_t jacks;
    le32_t streams;
    le32_t chmaps;
} __packed;

struct virtio_snd
{
    struct virtio_device *virtio_dev;

    struct virtio_queue *control_queue;
    struct virtio_queue *event_queue;
    struct virtio_queue *xmit_queue;
    struct virtio_queue *recv_queue;

    uint32_t num_jacks;
    uint32_t num_streams;
    uint32_t num_chmaps;
};

static int
virtio_snd_probe(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;
    printk("virtio_snd_probe\n");
    return 0;
}

static int
virtio_snd_negotiate(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;
    printk("virtio_snd_negotiate\n");
    return 0;
}

static int
virtio_snd_init_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;
    printk("virtio_snd_init_device\n");

    if(device->num_queues < 4) {
        wprintk("virtio-snd: Found virtio-snd device with an incorrect number of queues! (found=%d, required=4)\n",
                (int)device->num_queues);
        return -EINVAL;
    }

    struct virtio_snd *snd = kzmalloc(sizeof(*snd), KM_KERNEL);
    if(snd == NULL) {
        return -ENOMEM;
    }
    snd->virtio_dev = device;

    snd->control_queue = device->queues[0];
    snd->event_queue = device->queues[1];
    snd->xmit_queue = device->queues[2];
    snd->recv_queue = device->queues[3];

    virtio_device_cfg_readl(device, 0, &snd->num_jacks);
    snd->num_jacks = letoh32(snd->num_jacks);
    virtio_device_cfg_readl(device, 4, &snd->num_streams);
    snd->num_streams = letoh32(snd->num_streams);
    virtio_device_cfg_readl(device, 8, &snd->num_chmaps);
    snd->num_chmaps = letoh32(snd->num_chmaps);

    printk("virtio-snd: (num-jacks=0x%lx) (num-streams=0x%lx) (num-chmaps=0x%lx)\n",
            (ul_t)snd->num_jacks,
            (ul_t)snd->num_streams,
            (ul_t)snd->num_chmaps);

    return 0;
}

static int
virtio_snd_deinit_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    return -EUNIMPL;
}

static struct virtio_driver_ops
virtio_snd_virtio_driver_ops = {
    .probe = virtio_snd_probe,
    .negotiate = virtio_snd_negotiate,
    .init_device = virtio_snd_init_device,
    .deinit_device = virtio_snd_deinit_device,
};

static uint16_t
virtio_snd_virtio_ids[] = {
    25,
};

static struct virtio_driver
virtio_snd_virtio_driver = {
    .ops = &virtio_snd_virtio_driver_ops,
    .num_ids = sizeof(virtio_snd_virtio_ids) / sizeof(uint16_t),
    .ids = virtio_snd_virtio_ids,
};

static int
register_virtio_snd_driver(void)
{
    return register_virtio_driver(&virtio_snd_virtio_driver);
}
declare_init_desc(device, register_virtio_snd_driver, "Registered Virtio Sound Driver");
