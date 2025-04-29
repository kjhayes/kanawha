
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/net_dev.h>
#include <kanawha/stddef.h>
#include <kanawha/irq.h>
#include <drivers/virtio/driver.h>
#include <drivers/virtio/virtio.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/request.h>

static DECLARE_SPINLOCK(virtio_net_count_lock);
static unsigned long virtio_net_count = 0;

struct virtio_net {
    struct net_dev net_dev;
    struct virtio_device *virtio_dev;
    char *name;
};

static int
virtio_net_eth_send(
        struct net_dev *net,
        void *pkt,
        size_t pktlen)
{
    return -EUNIMPL;
}

static int
virtio_net_eth_read_mac(
        struct net_dev *net,
        struct eth_mac_addr *addr_out)
{
    memset(addr_out, 0, sizeof(*addr_out));
    return 0;
}

static struct net_driver
virtio_net_driver = {
    .eth_send = virtio_net_eth_send,
    .eth_read_mac = virtio_net_eth_read_mac,
};

static int
virtio_net_probe(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    dprintk("virtio_net_probe\n");
    return 0;
}

static int
virtio_net_negotiate(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    dprintk("virtio_net_negotiate\n");
    return 0;
}

static int
virtio_net_init_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    int res;

    dprintk("virtio_net_init_device\n");

    struct virtio_net *net = kmalloc(sizeof(struct virtio_net));
    if(net == NULL) {
        return -ENOMEM;
    }
    memset(net, 0, sizeof(struct virtio_net));

    unsigned long dev_index;
    spin_lock(&virtio_net_count_lock);
    dev_index = virtio_net_count;
    virtio_net_count++;
    spin_unlock(&virtio_net_count_lock);

#define NAMEBUFLEN 64
    char namebuf[NAMEBUFLEN];
    snprintk(namebuf, NAMEBUFLEN, "virtio-net-%ld", dev_index);
    namebuf[NAMEBUFLEN-1] = '\0';
#undef NAMEBUFLEN

    net->name = kstrdup(namebuf);
    if(net->name == NULL) {
        kfree(net);
        return res;
    }

    res = register_net_dev(
            &net->net_dev,
            net->name,
            &virtio_net_driver);
    if(res) {
        kfree(net->name);
        kfree(net);
        return res;
    }

    dprintk("virtio_net Initialized\n");

    return 0;
}

static int
virtio_net_deinit_device(
        struct virtio_driver *driver,
        struct virtio_device *device)
{
    return -EUNIMPL;
}

static struct virtio_driver_ops
virtio_net_virtio_driver_ops = {
    .probe = virtio_net_probe,
    .negotiate = virtio_net_negotiate,
    .init_device = virtio_net_init_device,
    .deinit_device = virtio_net_deinit_device,
};

static uint16_t
virtio_net_virtio_ids[] = {
    1,
};

static struct virtio_driver
virtio_net_virtio_driver = {
    .ops = &virtio_net_virtio_driver_ops,
    .num_ids = sizeof(virtio_net_virtio_ids) / sizeof(uint16_t),
    .ids = virtio_net_virtio_ids,
};

static int
register_virtio_net_driver(void)
{
    return register_virtio_driver(&virtio_net_virtio_driver);
}
declare_init_desc(device, register_virtio_net_driver, "Registered Virtio Network Driver");

