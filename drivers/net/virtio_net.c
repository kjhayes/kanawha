
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

struct virtio_net_config
{
    uint8_t mac[6];
    le16_t  status;
    le16_t  max_virtqueue_pairs;
    le16_t  mtu;
    le32_t  speed;
    uint8_t duplex;
    uint8_t rss_max_key_size;
    le16_t  rss_max_indirection_table_length;
    le32_t  supported_hash_types;
    le32_t  supported_tunnel_types;
};

#define  VIRTIO_NET_F_CSUM                 (0)
#define  VIRTIO_NET_F_GUEST_CSUM           (1)
#define  VIRTIO_NET_F_CTRL_GUEST_OFFLOADS  (2)
#define  VIRTIO_NET_F_MTU                  (3)
#define  VIRTIO_NET_F_MAC                  (5)
#define  VIRTIO_NET_F_GUEST_TSO4           (7)
#define  VIRTIO_NET_F_GUEST_TSO6           (8)
#define  VIRTIO_NET_F_GUEST_ECN            (9)
#define  VIRTIO_NET_F_GUEST_UFO            (10)
#define  VIRTIO_NET_F_HOST_TSO4            (11)
#define  VIRTIO_NET_F_HOST_TSO6            (12)
#define  VIRTIO_NET_F_HOST_ECN             (13)
#define  VIRTIO_NET_F_HOST_UFO             (14)
#define  VIRTIO_NET_F_MRG_RXBUF            (15)
#define  VIRTIO_NET_F_STATUS               (16)
#define  VIRTIO_NET_F_CTRL_VQ              (17)
#define  VIRTIO_NET_F_CTRL_RX              (18)
#define  VIRTIO_NET_F_CTRL_VLAN            (19)
#define  VIRTIO_NET_F_CTRL_RX_EXTRA        (20)
#define  VIRTIO_NET_F_GUEST_ANNOUNCE       (21)
#define  VIRTIO_NET_F_MQ                   (22)
#define  VIRTIO_NET_F_CTRL_MAC_ADDR        (23)
#define  VIRTIO_NET_F_HASH_TUNNEL          (51)
#define  VIRTIO_NET_F_VQ_NOTF_COAL         (52)
#define  VIRTIO_NET_F_NOTF_COAL            (53)
#define  VIRTIO_NET_F_GUEST_USO4           (54)
#define  VIRTIO_NET_F_GUEST_USO6           (55)
#define  VIRTIO_NET_F_HOST_USO             (56)
#define  VIRTIO_NET_F_HASH_REPORT          (57)
#define  VIRTIO_NET_F_GUEST_HDRLEN         (59)
#define  VIRTIO_NET_F_RSS                  (60)
#define  VIRTIO_NET_F_RSC_EXT              (61)
#define  VIRTIO_NET_F_STANDBY              (62)
#define  VIRTIO_NET_F_SPEED_DUPLEX         (63)

static DECLARE_SPINLOCK(virtio_net_count_lock);
static unsigned long virtio_net_count = 0;

struct virtio_net {
    struct net_dev net_dev;
    struct virtio_device *virtio_dev;
    char *name;
};

static int
virtio_net_eth_read_mac(
        struct net_dev *net_dev,
        struct eth_mac_addr *addr_out)
{
    int res;
    struct virtio_net *dev = container_of(net_dev, struct virtio_net, net_dev);

    for(int i = 0; i < 6; i++)
    {
        res = virtio_device_cfg_readb(
                dev->virtio_dev,
                offsetof(struct virtio_net_config, mac) + i,
                &addr_out->data[i]);
        if(res) {
            return res;
        }
    }
    return 0;
}

static struct net_driver
virtio_net_driver = {
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
    int res;

    dprintk("virtio_net_negotiate\n");

    int sup;

    sup = virtio_device_check_feature(device, VIRTIO_NET_F_MAC);
    switch(sup) {
        case 1: // Supported
            virtio_device_accept_feature(device, VIRTIO_NET_F_MAC);
            break;
        case 0: // Unsupported
        default: // ERROR
            printk("Failed to get virtio-net MAC address during negotiation!\n");
            return -EINVAL;
    }
    
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

    net->virtio_dev = device;

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

