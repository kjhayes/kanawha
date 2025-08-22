#ifndef __KANAWHA__BLOCK_DEVICE_H__
#define __KANAWHA__BLOCK_DEVICE_H__

#include <kanawha/registry.h>
#include <kanawha/ops.h>
#include <kanawha/types.h>
#include <kanawha/list.h>
#include <kanawha/atomic.h>
#include <kanawha/ptree.h>
#include <kanawha/stree.h>

struct blk_dev;
struct blk_driver;

#define BLOCK_DEVICE_WRITE_SIG(RET,ARG,...)\
RET(int)\
ARG(void *, data)\
ARG(size_t, base_sector)\
ARG(size_t, num_sectors)

#define BLOCK_DEVICE_READ_SIG(RET,ARG,...)\
RET(int)\
ARG(void *, data)\
ARG(size_t, base_sector)\
ARG(size_t, num_sectors)

#define BLOCK_DEVICE_NUM_SECTORS_SIG(RET,ARG,...)\
RET(ssize_t)

#define BLOCK_DEVICE_SECTOR_ORDER_SIG(RET,ARG,...)\
RET(order_t)

#define BLOCK_DEVICE_OP_LIST(OP, ...)\
OP(write, BLOCK_DEVICE_WRITE_SIG, ##__VA_ARGS__)\
OP(read, BLOCK_DEVICE_READ_SIG, ##__VA_ARGS__)\
OP(num_sectors, BLOCK_DEVICE_NUM_SECTORS_SIG, ##__VA_ARGS__)\
OP(sector_order, BLOCK_DEVICE_SECTOR_ORDER_SIG, ##__VA_ARGS__)\

struct blk_driver {
DECLARE_OP_LIST_PTRS(BLOCK_DEVICE_OP_LIST, struct blk_dev *);
};

struct blk_dev {
    struct registry_node registry_node;
    struct blk_driver *driver;
};

DEFINE_OP_LIST_WRAPPERS(
        BLOCK_DEVICE_OP_LIST,
        static inline,
        /* No Prefix */,
        blk_dev,
        DRIVER_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR);

DECLARE_REGISTRY(blk_dev);

#undef BLOCK_DEVICE_READ_SIG
#undef BLOCK_DEVICE_WRITE_SIG
#undef BLOCK_DEVICE_OP_LIST

#endif
