
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/blk_dev.h>
#include <kanawha/stddef.h>
#include <kanawha/irq.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>

static DECLARE_SPINLOCK(virtio_blk_count_lock);
static unsigned long virtio_blk_count = 0;

struct virtio_blk {
    struct blk_dev blk_dev;
    struct virtio_device *virtio_dev;
    char *name;
};

static int
virtio_blk_dev_request(
        struct blk_dev *dev,
        struct blk_dev_request *req)
{
    return -EUNIMPL;
}

static int
virtio_blk_dev_num_sectors(
        struct blk_dev *dev,
        size_t *sectors_out)
{
    return -EUNIMPL;
}

static struct blk_driver
virtio_blk_driver = {
    .request = virtio_blk_dev_request,
    .num_sectors = virtio_blk_dev_num_sectors,
};

static int
virtio_blk_probe(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    dprintk("virtio_blk_probe\n");
    return 0;
}

static int
virtio_blk_negotiate(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    dprintk("virtio_blk_negotiate\n");
    return 0;
}

static int
virtio_blk_init_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;

    dprintk("virtio_blk_init_device\n");

    if(device->num_queues != 2) {
        return -EINVAL;
    }

    struct virtio_blk *blk = kmalloc(sizeof(struct virtio_blk));
    if(blk == NULL) {
        return -ENOMEM;
    }
    memset(blk, 0, sizeof(struct virtio_blk));

    blk->virtio_dev = device;

    unsigned long dev_index;
    spin_lock(&virtio_blk_count_lock);
    dev_index = virtio_blk_count;
    virtio_blk_count++;
    spin_unlock(&virtio_blk_count_lock);

#define NAMEBUFLEN 64
    char namebuf[NAMEBUFLEN];
    snprintk(namebuf, NAMEBUFLEN, "virtio-blk-%ld", dev_index);
    namebuf[NAMEBUFLEN-1] = '\0';

    blk->name = kstrdup(namebuf);
    if(blk->name == NULL) {
        kfree(blk);
        return res;
    }

    res = register_blk_dev(
            &blk->blk_dev,
            blk->name,
            &virtio_blk_driver);
    if(res) {
        kfree(blk->name);
        kfree(blk);
        return res;
    }

    dprintk("virtio_blk Initialized\n");

    return 0;
}

static int
virtio_blk_deinit_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    return -EUNIMPL;
}

static struct virtio_driver_ops
virtio_blk_virtio_driver_ops = {
    .probe = virtio_blk_probe,
    .negotiate = virtio_blk_negotiate,
    .init_device = virtio_blk_init_device,
    .deinit_device = virtio_blk_deinit_device,
};

static uint16_t
virtio_blk_virtio_ids[] = {
    2,
};

static struct virtio_driver
virtio_blk_virtio_driver = {
    .ops = &virtio_blk_virtio_driver_ops,
    .num_ids = sizeof(virtio_blk_virtio_ids) / sizeof(uint16_t),
    .ids = virtio_blk_virtio_ids,
};

static int
register_virtio_blk_driver(void)
{
    return register_virtio_driver(&virtio_blk_virtio_driver);
}
declare_init_desc(device, register_virtio_blk_driver, "Registered Virtio Block Driver");

