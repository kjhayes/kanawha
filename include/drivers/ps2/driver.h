#ifndef __KANAWHA_DRIVERS__PS2_DRIVER_H__
#define __KANAWHA_DRIVERS__PS2_DRIVER_H__

#include <kanawha/list.h>
#include <kanawha/ops.h>

struct ps2_port;
struct ps2_driver;
struct ps2_driver_ops;

#define PS2_DRIVER_ATTACH_SIG(RET,ARG)\
RET(int)\
ARG(struct ps2_port *, port)

#define PS2_DRIVER_DEATTACH_SIG(RET,ARG)\
RET(int)\
ARG(struct ps2_port *, port)

#define PS2_DRIVER_OP_LIST(OP, ...)\
OP(attach, PS2_DRIVER_ATTACH_SIG, ##__VA_ARGS__)\
OP(deattach, PS2_DRIVER_DEATTACH_SIG, ##__VA_ARGS__)

struct ps2_dev_id {
    size_t len;
    uint8_t *id_bytes;
};

struct ps2_driver_ops {
DECLARE_OP_LIST_PTRS(PS2_DRIVER_OP_LIST, struct ps2_driver *);
};

struct ps2_driver
{
    struct ps2_driver_ops *ops;

    ilist_t ports;
    ilist_node_t global_node;
   
    size_t num_ids;
    struct ps2_dev_id ids[];
};

DEFINE_OP_LIST_WRAPPERS(
        PS2_DRIVER_OP_LIST,
        static inline,
        /* No Prefix */,
        ps2_driver,
        ->ops->,
        SELF_ACCESSOR);

#undef PS2_DRIVER_ATTACH_SIG
#undef PS2_DRIVER_OP_LIST

int
ps2_register_driver(
        struct ps2_driver *driver);
int
ps2_unregister_driver(
        struct ps2_driver *driver);

static inline void
ps2_driver_struct_init(
        struct ps2_driver *drv)
{
    ilist_init(&drv->ports);
}

#endif
