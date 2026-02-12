
#include <kanawha/dev/net/ipv4.h>
#include <kanawha/init.h>

static int
ipv4_dev_init(
        struct ipv4_dev *dev)
{
    printk("ipv4_dev registered: %s\n", ipv4_dev_get_name(dev));
    return 0;
}

static int
ipv4_dev_deinit(
        struct ipv4_dev *dev)
{
    printk("ipv4_dev unregistered: %s\n", ipv4_dev_get_name(dev));
    return 0;
}

DEFINE_DEV_TYPE(
        ipv4_dev,
        dev,
        ipv4_dev_init,
        ipv4_dev_deinit
        );

int
ipv4_dev_internal_on_recv(
        struct ipv4_dev *dev,
        struct ipv4_packet *pkt,
        size_t pktlen,
        unsigned long flags)
{
    return 0;
}

#ifdef CONFIG_LOG_IPV4DEV_REGISTRY_ON_LAUNCH
static int
dump_ipv4_dev_on_launch(void) {
    return dump_ipv4_dev_registry(do_printk);
}
declare_init(launch, dump_ipv4_dev_on_launch);
#endif
