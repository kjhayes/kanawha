
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/irq.h>
#include <kanawha/dev/net/eth.h>
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

struct virtio_net_hdr {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM 1
#define VIRTIO_NET_HDR_F_DATA_VALID 2
#define VIRTIO_NET_HDR_F_RSC_INFO 4
    uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE 0
#define VIRTIO_NET_HDR_GSO_TCPV4 1
#define VIRTIO_NET_HDR_GSO_UDP 3
#define VIRTIO_NET_HDR_GSO_TCPV6 4
#define VIRTIO_NET_HDR_GSO_UDP_L4 5
#define VIRTIO_NET_HDR_GSO_ECN 0x80
    uint8_t gso_type;
    le16_t hdr_len;
    le16_t gso_size;
    le16_t csum_start;
    le16_t csum_offset;
    le16_t num_buffers; // Not included without VIRTIO_NET_F_MRG_RXBUF if using legacy interface
//    le32_t hash_value; // (Only if VIRTIO_NET_F_HASH_REPORT negotiated)
//    le16_t hash_report; // (Only if VIRTIO_NET_F_HASH_REPORT negotiated)
//    le16_t padding_reserved; // (Only if VIRTIO_NET_F_HASH_REPORT negotiated)
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

struct virtio_net_queue_pair {
    struct virtio_queue *recv;
    struct virtio_queue *xmit;
};

struct virtio_net_eth_frame
{
    struct eth_frame eth_frame;
    struct virtio_request *req;
    dma_addr_t header_dma_buffer;
    size_t frame_len;
    dma_addr_t frame_dma_buffer;
};

struct virtio_net
{
    struct eth_dev eth_dev;
    struct virtio_device *virtio_dev;
    char *name;

    irq_lock_t recv_lock;
    unsigned receiving : 1;

    dma_addr_t recv_header;
    size_t num_recv_requests;
    struct virtio_request **recv_requests;
    dma_addr_t *recv_buffers;
    size_t recv_buffer_size;

    size_t num_queue_pairs;
    struct virtio_net_queue_pair queue_pairs[];
};

static inline size_t
virtio_net_hdr_len(struct virtio_net *dev)
{
    size_t size = sizeof(struct virtio_net_hdr);
    if(dev->virtio_dev->is_legacy) {
        size -= 2;
    }
    return size;
}

static int
virtio_net_eth_read_mac(
        struct eth_dev *eth_dev,
        struct eth_mac_addr *addr_out)
{
    int res;
    struct virtio_net *dev = container_of(eth_dev, struct virtio_net, eth_dev);

    memset(addr_out, 0, sizeof(*addr_out));

    for(int i = 0; i < 6; i++)
    {
        res = virtio_device_cfg_readb(
                dev->virtio_dev,
                offsetof(struct virtio_net_config, mac) + i,
                &addr_out->raw.data[i]);

        if(res) {
            return res;
        }
    }
    return 0;
}

static int
virtio_net_destroy_eth_frame(
        struct virtio_net *dev,
        struct virtio_net_eth_frame *frame)
{
    DEBUG_ASSERT(KERNEL_ADDR(frame));
    DEBUG_ASSERT(KERNEL_ADDR(frame->req));

    virtio_request_destroy(frame->req);
    frame->req = NULL;

    dma_free(frame->header_dma_buffer, virtio_net_hdr_len(dev));
    dma_free(frame->frame_dma_buffer, frame->frame_len);

    kfree(frame);

    return 0;
}

static struct eth_frame *
virtio_net_eth_alloc_frame(
        struct eth_dev *eth_dev,
        size_t frame_len,
        unsigned long flags)
{
    int res;

    if(flags != 0) {
        return NULL;
    }

    struct virtio_net *dev =
        container_of(eth_dev, struct virtio_net, eth_dev);

    struct virtio_net_eth_frame *frame = kmalloc(sizeof(*frame));
    if(frame == NULL) {
        return NULL;
    }
    memset(frame, 0, sizeof(*frame));

    res = dma_alloc(
            virtio_net_hdr_len(dev),
            alignof(struct virtio_net_hdr),
            0,
            &frame->header_dma_buffer);
    if(res) {
        kfree(frame);
        return NULL;
    }

    struct virtio_net_hdr *virtio_hdr = dma_virt_addr(frame->header_dma_buffer);
    memset(virtio_hdr, 0, sizeof(*virtio_hdr));
    virtio_hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;

    frame->frame_len = frame_len;
    res = dma_alloc(
            frame->frame_len,
            0,
            0,
            &frame->frame_dma_buffer);
    if(res) {
        dma_free(frame->header_dma_buffer, virtio_net_hdr_len(dev));
        kfree(frame);
        return NULL;
    }

    // queue pair index to use
    size_t pi = 0;

    struct virtio_net_queue_pair *qpair = &dev->queue_pairs[pi];
    
    frame->req = virtio_request_create(qpair->xmit);
    if(frame->req == NULL) {
        dma_free(frame->frame_dma_buffer, frame->frame_len);
        dma_free(frame->header_dma_buffer, virtio_net_hdr_len(dev));
        kfree(frame);
        return NULL;
    }

    res = virtio_request_append_input(
            frame->req,
            dma_phys_addr(frame->header_dma_buffer),
            virtio_net_hdr_len(dev));
    if(res) {
        virtio_request_destroy(frame->req);
        dma_free(frame->frame_dma_buffer, frame->frame_len);
        dma_free(frame->header_dma_buffer, virtio_net_hdr_len(dev));
        kfree(frame);
        return NULL;
    }

    res = virtio_request_append_input(
            frame->req,
            dma_phys_addr(frame->frame_dma_buffer),
            frame->frame_len);
    if(res) {
        virtio_request_destroy(frame->req);
        dma_free(frame->frame_dma_buffer, frame->frame_len);
        dma_free(frame->header_dma_buffer, virtio_net_hdr_len(dev));
        kfree(frame);
        return NULL;
    }

    struct eth_raw_frame *raw_frame = dma_virt_addr(frame->frame_dma_buffer);

    frame->eth_frame.dev = &dev->eth_dev;
    frame->eth_frame.data = raw_frame;

    return &frame->eth_frame;
}

static int
virtio_net_eth_send_frame(
        struct eth_dev *eth_dev,
        struct eth_frame *eth_frame)
{
    int res;

    struct virtio_net *dev =
        container_of(eth_dev, struct virtio_net, eth_dev);
    struct virtio_net_eth_frame *frame =
        container_of(eth_frame, struct virtio_net_eth_frame, eth_frame);

    DEBUG_ASSERT(KERNEL_ADDR(frame));
    DEBUG_ASSERT(KERNEL_ADDR(frame->req));

    res = virtio_request_launch(frame->req);
    if(res) {
        return res;
    }

    res = virtio_request_await(frame->req);
    if(res) {
        return res;
    }

    return 0;
}

static int
virtio_net_eth_drop_frame(
        struct eth_dev *eth_dev,
        struct eth_frame *eth_frame)
{
    int res;

    struct virtio_net *dev =
        container_of(eth_dev, struct virtio_net, eth_dev);
    struct virtio_net_eth_frame *frame =
        container_of(eth_frame, struct virtio_net_eth_frame, eth_frame);

    res = virtio_net_destroy_eth_frame(dev, frame);
    if(res) {
        return res;
    }

    return 0;
}
static void
virtio_net_eth_recv_request_callback(
        struct virtio_request *req,
        void *priv_state
        )
{
    int res;

    struct virtio_net *dev = priv_state;

    printk("VIRTIO-NET RECEIVED PACKET!\n");

    res = virtio_request_await(req);
    if(res) {
        wprintk("Failed to await virtio-net receive request in callback!\n");
        return;
    }

    int found = 0;
    for(size_t i = 0; i < dev->num_recv_requests; i++) {
        if(dev->recv_requests[i] == req)
        {
            found = 1;
            dma_addr_t dma_pkt = dev->recv_buffers[i];
            struct eth_frame *frame = dma_virt_addr(dma_pkt);

            size_t len = dev->recv_buffer_size;
            if(req->len_written < len) {
                len = req->len_written;
            }
            res = eth_dev_internal_on_recv(
                    &dev->eth_dev,
                    frame,
                    len,
                    0
                    );
            if(res) {
                // Weird but OK...
            }

            res = virtio_request_launch(req);
            if(res) {
                wprintk("Failed to re-launch virtio-net receive buffer request!\n");
            }

            break;
        }
    }

    if(found == 0) {
        wprintk("Failed to find receive buffer for completed virtio-net request!\n");
        return;
    }
}

static int
virtio_net_eth_begin_recv(
        struct eth_dev *eth_dev,
        unsigned long flags)
{
    int res;

    struct virtio_net *dev =
        container_of(eth_dev, struct virtio_net, eth_dev);

    irq_lock_acquire(&dev->recv_lock);

    if(dev->receiving) {
        irq_lock_release(&dev->recv_lock);
        return -EBUSY;
    }

    // Populate receive buffers
    
    res = dma_alloc(
            virtio_net_hdr_len(dev),
            alignof(struct virtio_net_hdr),
            DMA_PHYS_64,
            &dev->recv_header);
    if(res) {
        irq_lock_release(&dev->recv_lock);
        return res;
    }

    {
        // Set up the header
        struct virtio_net_hdr *hdr = dma_virt_addr(dev->recv_header);
        memset(hdr, 0, sizeof(*hdr));
    }

    dev->num_recv_requests = dev->queue_pairs[0].recv->queue_size / 2;
    dev->recv_buffer_size = 1514;

    dev->recv_buffers = kmalloc(sizeof(dma_addr_t) * dev->num_recv_requests);
    dev->recv_requests = kmalloc(sizeof(struct virtio_request*) * dev->num_recv_requests);

    if(dev->recv_buffers == NULL || dev->recv_requests == NULL) {
        dma_free(dev->recv_header, virtio_net_hdr_len(dev));
        return -ENOMEM;
    }

    for(size_t i = 0; i < dev->num_recv_requests; i++) {
        struct virtio_request *req = virtio_request_create(dev->queue_pairs[0].recv);
        if(req != NULL) {
            res = dma_alloc(
                    dev->recv_buffer_size,
                    0,
                    DMA_PHYS_64,
                    &dev->recv_buffers[i]);
            if(res) {
                virtio_request_destroy(req);
            } else {
                virtio_request_append_input(
                        req,
                        dma_phys_addr(dev->recv_header),
                        virtio_net_hdr_len(dev));
                virtio_request_append_output(
                        req,
                        dma_phys_addr(dev->recv_buffers[i]),
                        dev->recv_buffer_size);
                virtio_request_set_completion_callback(
                        req,
                        virtio_net_eth_recv_request_callback,
                        dev);
            }
        } else {
            res = -ENOMEM;
        }

        dev->recv_requests[i] = req;

        if(res) {
            for(size_t undo_i = 0; undo_i < i; undo_i++) {
                virtio_request_destroy(dev->recv_requests[i]);
                dma_free(dev->recv_buffers[i], dev->recv_buffer_size);
            }
            dma_free(dev->recv_header, virtio_net_hdr_len(dev));
            return res;
        }
    }

    dev->receiving = 1;

    for(size_t i = 0; i < dev->num_recv_requests; i++) {
        DEBUG_ASSERT(KERNEL_ADDR(dev->recv_requests[i]));
        res = virtio_request_launch(dev->recv_requests[i]);
        if(res) {
            wprintk("virtio-net: Failed to launch virtio request to begin receiving packets!\n");
        }
    }

    irq_lock_release(&dev->recv_lock);

    return 0;
}

static int
virtio_net_eth_end_recv(
        struct eth_dev *eth_dev,
        unsigned long flags)
{
    int res;

    struct virtio_net *dev =
        container_of(eth_dev, struct virtio_net, eth_dev);

    irq_lock_acquire(&dev->recv_lock);

    if(!dev->receiving) {
        irq_lock_release(&dev->recv_lock);
        return -EINVAL;
    }

    // Free all of the requests and buffers
    for(size_t i = 0; i < dev->num_recv_requests; i++) {
        virtio_request_destroy(dev->recv_requests[i]);
        dma_free(dev->recv_buffers[i], dev->recv_buffer_size);
        dma_free(dev->recv_header, virtio_net_hdr_len(dev));
        kfree(dev->recv_buffers);
        kfree(dev->recv_requests);
    }

    dev->receiving = 0;

    irq_lock_release(&dev->recv_lock);

    return 0;
}

static struct eth_driver
virtio_eth_driver = {
    .read_mac = virtio_net_eth_read_mac,
    .alloc_frame = virtio_net_eth_alloc_frame,
    .send_frame = virtio_net_eth_send_frame,
    .drop_frame = virtio_net_eth_drop_frame,
    .begin_recv = virtio_net_eth_begin_recv,
    .end_recv = virtio_net_eth_end_recv,
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

    size_t num_queue_pairs = 1;

    struct virtio_net *net = kmalloc(sizeof(struct virtio_net) + (sizeof(struct virtio_net_queue_pair) * num_queue_pairs));
    if(net == NULL) {
        return -ENOMEM;
    }
    memset(net, 0, sizeof(struct virtio_net));
    net->virtio_dev = device;

    irq_lock_init(&net->recv_lock);
    net->receiving = 0;

    // Find and activate all of the queue pairs
    net->num_queue_pairs = num_queue_pairs;
    if(net->virtio_dev->num_queues < num_queue_pairs * 2) {
        kfree(net);
        return -EINVAL;
    }

    for(size_t i = 0; i < net->num_queue_pairs; i++) {
        net->queue_pairs[i].recv = net->virtio_dev->queues[2*i];
        net->queue_pairs[i].xmit = net->virtio_dev->queues[(2*i) + 1];

        res = virtio_queue_enable(net->queue_pairs[i].recv);
        if(!res) {
            res = virtio_queue_enable(net->queue_pairs[i].xmit);
            if(res) {
                virtio_queue_disable(net->queue_pairs[i].recv);
            }
        }
        if(res) {
            // Both of the current "i" queues should be disabled
            for(int undo_i = 0; undo_i < i; undo_i++) {
                virtio_queue_disable(net->queue_pairs[undo_i].recv);
                virtio_queue_disable(net->queue_pairs[undo_i].xmit);
            }
            kfree(net);
            return res;
        }
    }

    // Register the device
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
        for(int i = 0; i < net->num_queue_pairs; i++) {
            virtio_queue_disable(net->queue_pairs[i].recv);
            virtio_queue_disable(net->queue_pairs[i].xmit);
        }
        kfree(net);
        return res;
    }

    net->eth_dev.driver = &virtio_eth_driver;

    res = register_eth_dev(
            &net->eth_dev,
            net->name);
    if(res) {
        for(int i = 0; i < net->num_queue_pairs; i++) {
            virtio_queue_disable(net->queue_pairs[i].recv);
            virtio_queue_disable(net->queue_pairs[i].xmit);
        }
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
register_virtio_eth_driver(void)
{
    return register_virtio_driver(&virtio_net_virtio_driver);
}
declare_init_desc(device, register_virtio_eth_driver, "Registered Virtio Network Driver");

