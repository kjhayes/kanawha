
#include <kanawha/dev/net/eth.h>
#include <kanawha/registry.h>
#include <kanawha/init.h>

struct eth_dev_recv_hook
{
    struct eth_dev *dev;
    void *priv_state;
    int(*on_recv)(
            struct eth_dev *dev,
            void *buffer,
            size_t buflen,
            unsigned long flags,
            void *priv_state);
    ilist_node_t list_node;
};

static int
eth_dev_init(struct eth_dev *dev)
{
    irq_lock_init(&dev->recv_callback_lock);
    ilist_init(&dev->recv_callback_list);
    printk("eth_dev registered: %s\n", eth_dev_get_name(dev));
    return 0;
}

static int
eth_dev_deinit(struct eth_dev *dev)
{
    irq_lock_acquire(&dev->recv_callback_lock);
    ilist_node_t *list_node;
    ilist_for_each(list_node, &dev->recv_callback_list) {
        struct eth_dev_recv_hook *hook =
            container_of(list_node, struct eth_dev_recv_hook, list_node);
        hook->dev = NULL;
    }
    irq_lock_release(&dev->recv_callback_lock);

    printk("eth_dev unregistered: %s\n", eth_dev_get_name(dev));
    return 0;
}

// External
struct eth_dev_recv_hook *
hook_eth_dev_receive(
        struct eth_dev *dev,
        int(*on_recv)(
            struct eth_dev *dev,
            void *buffer,
            size_t buflen,
            unsigned long flags,
            void *priv_state),
        void *priv_state
        )
{
    int res;

    struct eth_dev_recv_hook *hook;
    hook = kmalloc(sizeof(*hook), KM_KERNEL);
    if(hook == NULL) {
        return NULL;
    }
    hook->on_recv = on_recv;
    hook->priv_state = priv_state;

    irq_lock_acquire(&dev->recv_callback_lock);
    if(ilist_empty(&dev->recv_callback_list)) {
        res = eth_dev_begin_recv(dev, 0);
        if(res) {
            irq_lock_release(&dev->recv_callback_lock);
            kfree(hook);
            return NULL;
        }
        dev->receiving = 1;
    }
    ilist_push_tail(&dev->recv_callback_list, &hook->list_node);
    irq_lock_release(&dev->recv_callback_lock);

    return hook;
}

int
unhook_eth_dev_receive(
        struct eth_dev_recv_hook *hook)
{
    int res;

    if(hook->dev != NULL) {
        irq_lock_acquire(&hook->dev->recv_callback_lock);
        if(hook->dev != NULL) {
            ilist_remove(&hook->dev->recv_callback_list, &hook->list_node);
            if(ilist_empty(&hook->dev->recv_callback_list)) {
                res = eth_dev_end_recv(hook->dev, 0);
                if(res) {
                    // Uh-Oh (Not necessarily panic worthy though)
                    wprintk("Failed to stop receiving on ethernet device \"%s\"!\n",
                            eth_dev_get_name(hook->dev));
                } else {
                    hook->dev->receiving = 0;
                }
            }
            irq_lock_release(&hook->dev->recv_callback_lock);
        }
    }

    kfree(hook);

    return 0;
}

// Internal
int
eth_dev_internal_on_recv(
        struct eth_dev *dev,
        void *buffer,
        size_t buflen,
        unsigned long flags)
{
    irq_lock_acquire(&dev->recv_callback_lock);
    ilist_node_t *list_node;
    ilist_for_each(list_node, &dev->recv_callback_list) {
        struct eth_dev_recv_hook *hook =
            container_of(list_node, struct eth_dev_recv_hook, list_node);

        DEBUG_ASSERT(hook->dev == dev);
        DEBUG_ASSERT(KERNEL_ADDR(hook->on_recv));

        int hook_ret = (*hook->on_recv)(
                dev,
                buffer,
                buflen,
                flags,
                hook->priv_state);

        if(hook_ret == ETH_RECV_IGNORE || hook_ret == ETH_RECV_FORWARD) {
            continue;
        } else {
            break;
        }
    }
    irq_lock_release(&dev->recv_callback_lock);

    return 0;
}

DEFINE_REGISTRY(
        eth_dev,
        registry_node,
        eth_dev_init,
        eth_dev_deinit);

#ifdef CONFIG_LOG_ETHDEV_REGISTRY_ON_LAUNCH
static int
dump_eth_dev_on_launch(void) {
    return dump_eth_dev_registry(do_printk);
}
declare_init(launch, dump_eth_dev_on_launch);
#endif
