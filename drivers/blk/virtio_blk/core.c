
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/dev/blk.h>
#include <kanawha/stddef.h>
#include <kanawha/irq.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>

#define VIRTIO_BLK_T_IN 0
#define VIRTIO_BLK_T_OUT 1
#define VIRTIO_BLK_T_FLUSH 4
#define VIRTIO_BLK_T_GET_ID 8
#define VIRTIO_BLK_T_GET_LIFETIME 10
#define VIRTIO_BLK_T_DISCARD 11
#define VIRTIO_BLK_T_WRITE_ZEROES 13
#define VIRTIO_BLK_T_SECURE_ERASE 14

#define VIRTIO_BLK_S_OK 0
#define VIRTIO_BLK_S_IOERR 1
#define VIRTIO_BLK_S_UNSUPP 2

struct virtio_blk_req {
    le32_t type;
    le32_t reserved;
    le64_t sector;
};

static DECLARE_SPINLOCK(virtio_blk_count_lock);
static unsigned long virtio_blk_count = 0;

struct virtio_blk {
    struct blk_dev blk_dev;

    size_t num_sectors;

    struct virtio_device *virtio_dev;
    struct virtio_queue *queue;
    char *name;
};

static int
virtio_blk_dev_write(
        struct blk_dev *dev,
        void *data,
        size_t base_sector,
        size_t num_sectors
        )
{
    int res;

    struct virtio_blk *blk = container_of(dev, struct virtio_blk, blk_dev);

    struct virtio_blk_req req;
    req.type = VIRTIO_BLK_T_OUT;
    req.sector = base_sector;

    uint8_t status;

    void * input_datas[2] = { &req, data };
    size_t input_sizes[2] = { sizeof(struct virtio_blk_req), 512ULL * num_sectors };

    void * output_datas[1] = { &status };
    size_t output_sizes[1] = { 1 };

    res = virtio_transact(
            blk->queue,
            2,
            input_datas,
            input_sizes,
            1,
            output_datas,
            output_sizes);
    if(res) {
        return res;
    }

    switch(status) {
        case VIRTIO_BLK_S_OK: return 0;
        case VIRTIO_BLK_S_IOERR: return -EIO;
        case VIRTIO_BLK_S_UNSUPP: return -EUNIMPL;
        default: return -EINVAL;
    }
}

static int
virtio_blk_dev_read(
        struct blk_dev *dev,
        void *data,
        size_t base_sector,
        size_t num_sectors
        )
{
    int res;

    dprintk("virtio_blk_read (base_sector=0x%lx, num_sectors=0x%lx)\n",
            base_sector,
            num_sectors);

    struct virtio_blk *blk = container_of(dev, struct virtio_blk, blk_dev);

    struct virtio_blk_req req;
    req.type = VIRTIO_BLK_T_IN;
    req.sector = base_sector;

    uint8_t status;

    void * input_datas[1] = { &req };
    size_t input_sizes[1] = { sizeof(struct virtio_blk_req) };

    void * output_datas[2] = { data, &status };
    size_t output_sizes[2] = { 512ULL * num_sectors, 1 };

    res = virtio_transact(
            blk->queue,
            1,
            input_datas,
            input_sizes,
            2,
            output_datas,
            output_sizes);
    if(res) {
        dprintk("virtio_blk_read: virtio_transact returned %s\n", errnostr(res));
        return res;
    }

    switch(status) {
        case VIRTIO_BLK_S_OK:
            dprintk("virtio_blk_read SUCCESS\n");
            return 0;
        case VIRTIO_BLK_S_IOERR:
            dprintk("virtio_blk_read IOERR\n");
            return -EIO;
        case VIRTIO_BLK_S_UNSUPP:
            dprintk("virtio_blk_read UNSUPP\n");
            return -EUNIMPL;
        default:
            dprintk("virtio_blk_read UNKNOWN ERROR\n");
            return -EINVAL;
    }
}

static ssize_t
virtio_blk_num_sectors(
        struct blk_dev *blk_dev)
{
    struct virtio_blk *blk =
        container_of(blk_dev, struct virtio_blk, blk_dev);
    return blk->num_sectors;
}

static order_t
virtio_blk_sector_order(
        struct blk_dev *blk_dev)
{
    return 9;
}

static struct blk_driver
virtio_blk_driver = {
    .read = virtio_blk_dev_read,
    .write = virtio_blk_dev_write,
    .num_sectors = virtio_blk_num_sectors,
    .sector_order = virtio_blk_sector_order,
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

    if(device->num_queues < 1) {
        return -EINVAL;
    }

    size_t capacity;
    {
    le64_t le_capacity;
    res = virtio_device_cfg_readq(device, 0, &le_capacity);
    if(res) {
        return -EINVAL;
    }
    capacity = letoh64(le_capacity);
    }

    dprintk("virtio-blk (capacity = 0x%lx sectors)\n", capacity);

    struct virtio_blk *blk = kmalloc(sizeof(struct virtio_blk));
    if(blk == NULL) {
        return -ENOMEM;
    }
    memset(blk, 0, sizeof(struct virtio_blk));

    blk->virtio_dev = device;
    blk->queue = device->queues[0];
    DEBUG_ASSERT(KERNEL_ADDR(blk->queue));

    res = virtio_queue_enable(blk->queue);
    if(res) {
        kfree(blk);
        return res;
    }

    unsigned long dev_index;
    spin_lock(&virtio_blk_count_lock);
    dev_index = virtio_blk_count;
    virtio_blk_count++;
    spin_unlock(&virtio_blk_count_lock);

#define NAMEBUFLEN 64
    char namebuf[NAMEBUFLEN];
    snprintk(namebuf, NAMEBUFLEN, "virtio-blk-%ld", dev_index);
    namebuf[NAMEBUFLEN-1] = '\0';
#undef NAMEBUFLEN

    blk->name = kstrdup(namebuf);
    if(blk->name == NULL) {
        kfree(blk);
        return res;
    }

    blk->num_sectors = capacity;

    res = register_blk_dev(
            &blk->blk_dev,
            blk->name,
            &virtio_blk_driver
            );
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

