
#include <kanawha/net/network.h>
#include <kanawha/init.h>

static int
network_init(
        struct network *network)
{
    return 0;
}

static int
network_deinit(
        struct network *network)
{
    return 0;
}

DEFINE_REGISTRY(
        network,
        registry_node,
        network_init,
        network_deinit);

/*
 * Default Network
 */

static int default_network_registered = 0;
static struct network default_network;
struct network *
network_get_default(void) {
    if(!default_network_registered) {
        return NULL;
    }
    return &default_network;
}

static int
register_default_network(void)
{
    return register_network(
            &default_network,
            "default");
}
declare_init_desc(bus, register_default_network, "Registering Default Network");

