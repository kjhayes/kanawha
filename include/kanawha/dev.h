#ifndef __KANAWHA__DEV_H__
#define __KANAWHA__DEV_H__

#include <kanawha/registry.h>

struct dev
{
    struct registry_node registry_node;
};

#define DECLARE_DEV_TYPE(DNAME) DECLARE_REGISTRY(DNAME)

#define DEV_NO_INIT_FUNCTION REGISTRY_NO_INIT_FUNCTION
#define DEV_NO_DEINIT_FUNCTION REGISTRY_NO_DEINIT_FUNCTION

#define DEFINE_DEV_TYPE(DNAME, DEV_FIELD, INIT_FUNCTION, DEINIT_FUNCTION)      \
    DEFINE_REGISTRY(DNAME,                                                     \
                    DEV_FIELD.registry_node,                                   \
                    INIT_FUNCTION,                                             \
                    DEINIT_FUNCTION)

#endif
