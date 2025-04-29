
#include <kanawha/net_dev.h>
#include <kanawha/stree.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>

static DECLARE_SPINLOCK(net_dev_lock);
static DECLARE_STREE(net_dev_tree);

int
register_net_dev(
        struct net_dev *dev,
        const char *name,
        struct net_driver *driver)
{
    int res;

    spin_lock(&net_dev_lock);

    dev->driver = driver;
    dev->net_dev_node.key = name;

    struct stree_node *existing = stree_get(&net_dev_tree, name);
    if(existing != NULL) {
        spin_unlock(&net_dev_lock);
        return -ENXIO;
    }

    res = stree_insert(&net_dev_tree, &dev->net_dev_node);
    if(res) {
        spin_unlock(&net_dev_lock);
        return res;
    }

    spin_unlock(&net_dev_lock);

    struct eth_mac_addr addr;
    res = net_dev_eth_read_mac(dev, &addr);
    if(res) {
        printk("Failed to get registered network device MAC address!\n");
        return res;
    }
    printk("Registered Network Device \"%s\" MAC=[",
            name);
    dump_eth_mac_addr(do_printk, &addr);
    printk("]\n");
    return 0;
}

struct net_dev *
net_dev_find(const char *name)
{
    spin_lock(&net_dev_lock);
    struct stree_node *node = stree_get(&net_dev_tree, name);
    spin_unlock(&net_dev_lock);
    if(node == NULL) {
        return NULL;
    }
    return container_of(node, struct net_dev, net_dev_node);
}

