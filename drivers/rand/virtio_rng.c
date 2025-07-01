
#include <kanawha/dev/rand.h>

#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>

static DECLARE_SPINLOCK(virtio_rng_count_lock);
static unsigned long virtio_rng_count = 0;

#define VIRTIO_RNG_BUFSIZE 0x1000

struct virtio_rng_device
{
    struct rand_dev rand_dev;

    char *name;

    struct virtio_queue *request_queue;

    size_t data_avail;

    size_t bufsize;
    dma_addr_t buffer;

    struct virtio_request *request;
};

static ssize_t
virtio_rng_read(
        struct rand_dev *rand_dev,
        void *buffer,
        size_t buflen)
{
    int res;

    struct virtio_rng_device *dev =
        container_of(rand_dev, struct virtio_rng_device, rand_dev);
    
    if(dev->data_avail == 0) {
        dprintk("Launching Request queue=%p, index=0x%lx\n", dev->request->queue, dev->request->queue->index);
        res = virtio_request_launch(dev->request);
        if(res) {
            return res;
        }
        dprintk("Awaiting Request queue=%p, index=0x%lx\n", dev->request->queue, dev->request->queue->index);
        res = virtio_request_await(dev->request);
        if(res) {
            return res;
        }
        dprintk("Received Response queue=%p, index=0x%lx\n", dev->request->queue, dev->request->queue->index);
        DEBUG_ASSERT_MSG(dev->request->len_written <= VIRTIO_RNG_BUFSIZE, "WTF (len_written=0x%lx)\n", dev->request->len_written);
        dev->data_avail = dev->request->len_written;
    }

    if(dev->data_avail == 0) {
        return 0;
    }

    size_t offset = VIRTIO_RNG_BUFSIZE - dev->data_avail;
    size_t to_copy = 0;

    if(dev->data_avail < buflen) {
        to_copy = dev->data_avail;
        dev->data_avail = 0;
    } else {
        dev->data_avail -= buflen;
        to_copy = buflen;
    }

    memcpy(buffer, dma_virt_addr(dev->buffer) + offset, to_copy);
    return to_copy;
}


static struct rand_driver virtio_rng_rand_driver = {
    .read = virtio_rng_read,
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

    dprintk("virtio_rng_init_device\n");

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

    res = virtio_queue_enable(rng->request_queue);
    if(res) {
        kfree(rng);
        return res;
    }

    rng->bufsize = VIRTIO_RNG_BUFSIZE;
    res = dma_alloc(
            rng->bufsize,
            0,
            DMA_PHYS_64,
            &rng->buffer);
    if(res) {
        virtio_queue_disable(rng->request_queue);
        kfree(rng);
        return res;
    }

    rng->request = virtio_request_create(device->queues[0]);
    if(rng->request == NULL) {
        virtio_queue_disable(rng->request_queue);
        dma_free(rng->buffer, rng->bufsize);
        kfree(rng);
        return -ENOMEM;
    }

    res = virtio_request_append_output(
            rng->request,
            dma_phys_addr(rng->buffer),
            rng->bufsize);
    if(res) {
        virtio_queue_disable(rng->request_queue);
        virtio_request_destroy(rng->request);
        dma_free(rng->buffer, rng->bufsize);
        kfree(rng);
        return res;
    }

    rng->data_avail = 0;

    unsigned long dev_index;
    spin_lock(&virtio_rng_count_lock);
    dev_index = virtio_rng_count;
    virtio_rng_count++;
    spin_unlock(&virtio_rng_count_lock);

#define NAMEBUFLEN 64
    char namebuf[NAMEBUFLEN];
    snprintk(namebuf, NAMEBUFLEN, "virtio-rng-%ld", dev_index);
    namebuf[NAMEBUFLEN-1] = '\0';

    rng->name = kstrdup(namebuf);
    if(rng->name == NULL) {
        virtio_queue_disable(rng->request_queue);
        virtio_request_destroy(rng->request);
        dma_free(rng->buffer, rng->bufsize);
        kfree(rng);
        return res;
    }

    rng->rand_dev.driver = &virtio_rng_rand_driver;

    res = register_rand_dev(
            &rng->rand_dev,
            rng->name);
    if(res) {
        virtio_queue_disable(rng->request_queue);
        virtio_request_destroy(rng->request);
        dma_free(rng->buffer, rng->bufsize);
        kfree(rng->name);
        kfree(rng);
        return res;
    }

    dprintk("virtio_rng Initialized\n");

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
declare_init_desc(device, register_virtio_rng_driver, "Registering Virtio RNG Driver");

