#ifndef __KANAWHA__DEVICE_H__
#define __KANAWHA__DEVICE_H__

#include <kanawha/ops.h>
#include <kanawha/list.h>

struct device;

// Follows strncpy semantics
#define DEVICE_READ_NAME_SIG(RET,ARG) \
RET(int)\
ARG(char *, buf)\
ARG(size_t, size)

#define DEVICE_OP_LIST(OP, ...)\
OP(read_name, DEVICE_READ_NAME_SIG, ##__VA_ARGS__)

struct device_ops {
DECLARE_OP_LIST_PTRS(DEVICE_OP_LIST, struct device *)
};

struct device
{
    struct device_ops *ops;

    struct device *parent;

    size_t num_children;
    ilist_t children;

    ilist_node_t parent_node;
    ilist_node_t global_node;
};

int
register_device(
        struct device *device,
        struct device_ops *ops,
        struct device *parent);

int
unregister_device(
        struct device *device);

/*
 * Helper Functions
 */

int dump_devices(printk_f *printer);
int dump_device_hierarchy(printk_f *printer);

/*
 * Actually define the functions which can be called on a device
 * (And so some macro "clean up" because this is a header)
 */

DEFINE_OP_LIST_WRAPPERS(
        DEVICE_OP_LIST,
        static inline,
        /*No Prefix*/,
        device,
        OPS_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR)

#undef DEVICE_GET_NAME_SIG
#undef DEVICE_OP_LIST

#endif
