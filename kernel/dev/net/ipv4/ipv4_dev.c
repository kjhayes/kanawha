
#include <kanawha/dev/net/ipv4.h>

static int
ipv4_dev_init(
        struct ipv4_dev *dev)
{
    return 0;
}

static int
ipv4_dev_deinit(
        struct ipv4_dev *dev)
{
    return 0;
}

DEFINE_REGISTRY(
        ipv4_dev,
        registry_node,
        ipv4_dev_init,
        ipv4_dev_deinit
        );

int
ipv4_dev_internal_on_recv(
        struct ipv4_dev *dev,
        void *buffer,
        size_t buflen,
        unsigned long flags)
{
    return 0;
}

