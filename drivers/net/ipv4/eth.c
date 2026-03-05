#ifndef __KANAWHA__DRIVERS_NET_IPV4_ETH_H__
#define __KANAWHA__DRIVERS_NET_IPV4_ETH_H__

// IPv4 over Ethernet

#include <kanawha/dev/net/eth.h>
#include <kanawha/dev/net/ipv4.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>

DEFINE_LOCAL_IRQ_LOCK(ipv4_over_eth_dev_eth_dev_tree_lock);
static DECLARE_PTREE(ipv4_over_eth_dev_eth_dev_tree);

struct ipv4_over_eth_dev
{
    struct eth_dev *eth_dev;
    struct ipv4_dev ipv4_dev;

    struct ptree_node eth_dev_node;
};

struct ipv4_over_eth_packet
{
    struct ipv4_packet ipv4_packet;
    struct eth_frame *eth_frame;
};

static inline struct ipv4_over_eth_dev *
lookup_eth_dev(struct eth_dev *dev)
{
    ipv4_over_eth_dev_eth_dev_tree_lock_acquire();
    struct ptree_node *pnode =
        ptree_get(&ipv4_over_eth_dev_eth_dev_tree, (uintptr_t)dev);
    ipv4_over_eth_dev_eth_dev_tree_lock_release();
    if(pnode == NULL)
    {
        return NULL;
    }

    return container_of(pnode, struct ipv4_over_eth_dev, eth_dev_node);
}

static struct ipv4_packet *
ipv4_over_eth_alloc_packet(struct ipv4_dev *ipv4_dev,
                           size_t pkt_size,
                           unsigned long flags)
{
    int res;

    struct ipv4_over_eth_dev *dev =
        container_of(ipv4_dev, struct ipv4_over_eth_dev, ipv4_dev);

    struct eth_mac_addr mac_addr;
    res = eth_dev_read_mac(dev->eth_dev, &mac_addr);
    if(res)
    {
        return NULL;
    }

    size_t frame_len = sizeof(struct eth_raw_frame) + pkt_size;
    struct eth_frame *frame = eth_dev_alloc_frame(dev->eth_dev, frame_len, 0);

    frame->data->hdr.src_addr = mac_addr.raw;
    frame->data->hdr.dst_addr = ETH_MAC_ADDR_BROADCAST.raw;
    frame->data->hdr.type = htobe16(ETH_TYPE_IPV4);

    struct ipv4_over_eth_packet *pkt = kmalloc(sizeof(*pkt), KM_KERNEL);
    pkt->eth_frame = frame;
    pkt->ipv4_packet.data = (struct ipv4_raw_packet *)frame->data->data;
    pkt->ipv4_packet.dev = ipv4_dev;

    return &pkt->ipv4_packet;
}

static int
ipv4_over_eth_send_packet(struct ipv4_dev *ipv4_dev,
                          struct ipv4_packet *ipv4_pkt)
{
    struct ipv4_over_eth_packet *pkt =
        container_of(ipv4_pkt, struct ipv4_over_eth_packet, ipv4_packet);

    return eth_frame_send(pkt->eth_frame);
}

static int
ipv4_over_eth_drop_packet(struct ipv4_dev *ipv4_dev,
                          struct ipv4_packet *ipv4_pkt)
{
    int res;
    struct ipv4_over_eth_packet *pkt =
        container_of(ipv4_pkt, struct ipv4_over_eth_packet, ipv4_packet);

    res = eth_frame_drop(pkt->eth_frame);
    if(res)
    {
        return res;
    }

    kfree(pkt);

    return 0;
}

static int
ipv4_over_eth_begin_recv(struct ipv4_dev *dev, unsigned long flags)
{
    return -EUNIMPL;
}

static int
ipv4_over_eth_end_recv(struct ipv4_dev *dev, unsigned long flags)
{
    return -EUNIMPL;
}

static struct ipv4_driver ipv4_over_eth_driver = {
    .alloc_packet = ipv4_over_eth_alloc_packet,
    .send_packet = ipv4_over_eth_send_packet,
    .drop_packet = ipv4_over_eth_drop_packet,
    .begin_recv = ipv4_over_eth_begin_recv,
    .end_recv = ipv4_over_eth_end_recv,
};

static int
ipv4_attach_to_eth_dev(struct eth_dev *eth_dev)
{
    int res;

    struct ipv4_over_eth_dev *dev = kmalloc(sizeof(*dev), KM_KERNEL);
    if(dev == NULL)
    {
        return -ENOMEM;
    }
    memset(dev, 0, sizeof(*dev));

    dev->eth_dev = eth_dev;

    ipv4_over_eth_dev_eth_dev_tree_lock_acquire();
    res = ptree_insert(&ipv4_over_eth_dev_eth_dev_tree,
                       &dev->eth_dev_node,
                       (uintptr_t)eth_dev);
    if(res)
    {
        ipv4_over_eth_dev_eth_dev_tree_lock_release();
        kfree(dev);
        return res;
    }
    ipv4_over_eth_dev_eth_dev_tree_lock_release();

    dev->ipv4_dev.driver = &ipv4_over_eth_driver;

    res = register_ipv4_dev(&dev->ipv4_dev, eth_dev_get_name(eth_dev));
    if(res)
    {
        ipv4_over_eth_dev_eth_dev_tree_lock_acquire();
        ptree_remove(&ipv4_over_eth_dev_eth_dev_tree, (uintptr_t)eth_dev);
        ipv4_over_eth_dev_eth_dev_tree_lock_release();
        kfree(dev);
        return res;
    }

    return 0;
}

static int
ipv4_deattach_from_eth_dev(struct ipv4_over_eth_dev *dev)
{
    ipv4_over_eth_dev_eth_dev_tree_lock_acquire();
    ptree_remove(&ipv4_over_eth_dev_eth_dev_tree, (uintptr_t)dev->eth_dev);
    ipv4_over_eth_dev_eth_dev_tree_lock_release();

    unregister_ipv4_dev(&dev->ipv4_dev);

    kfree(dev);

    return 0;
}

static void
ipv4_on_eth_dev_register(struct eth_dev *eth_dev)
{
    int res;

    printk("Installing IPv4 Device on Ethernet Device \"%s\"\n",
           eth_dev_get_name(eth_dev));

    res = ipv4_attach_to_eth_dev(eth_dev);
    if(res)
    {
        eprintk("Failed to attach IPv4 Device to Ethernet Device \"%s\"!\n",
                eth_dev_get_name(eth_dev));
    }

    return;
}

static void
ipv4_on_eth_dev_unregister(struct eth_dev *eth_dev)
{
    struct ipv4_over_eth_dev *dev = lookup_eth_dev(eth_dev);
    if(dev)
    {
        printk("Uninstalling IPv4 Device from Ethernet Device \"%s\"\n",
               eth_dev_get_name(eth_dev));
        ipv4_deattach_from_eth_dev(dev);
    }
}

static struct eth_dev_registry_hook *ipv4_ethernet_hook = NULL;
static int
ipv4_ethernet_install_hook(void)
{
    struct eth_dev_registry_hook *hook;
    hook = hook_eth_dev_registry(ipv4_on_eth_dev_register,
                                 ipv4_on_eth_dev_unregister);
    if(hook == NULL)
    {
        return -EFAULT;
    }

    ipv4_ethernet_hook = hook;

    return 0;
}
declare_init(device, ipv4_ethernet_install_hook);

#endif
