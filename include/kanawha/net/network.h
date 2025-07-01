#ifndef __KANAWHA__NET_NETWORK_H__
#define __KANAWHA__NET_NETWORK_H__

#include <kanawha/registry.h>

struct network {
    struct registry_node registry_node;
};

DECLARE_REGISTRY(network);

struct network *
network_get_default(void);

#endif
