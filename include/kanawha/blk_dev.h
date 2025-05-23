#ifndef __KANAWHA__BLOCK_DEVICE_H__
#define __KANAWHA__BLOCK_DEVICE_H__

#include <kanawha/types.h>
#include <kanawha/ops.h>
#include <kanawha/list.h>
#include <kanawha/atomic.h>
#include <kanawha/ptree.h>
#include <kanawha/stree.h>
#include <kanawha/fs/sys/vfs.h>

struct blk_dev;
struct blk_driver;

#define BLOCK_DEVICE_WRITE_SIG(RET,ARG)\
RET(int)\
ARG(void *, data)\
ARG(size_t, base_sector)\
ARG(size_t, num_sectors)

#define BLOCK_DEVICE_READ_SIG(RET,ARG)\
RET(int)\
ARG(void *, data)\
ARG(size_t, base_sector)\
ARG(size_t, num_sectors)

#define BLOCK_DEVICE_OP_LIST(OP, ...)\
OP(write, BLOCK_DEVICE_WRITE_SIG, ##__VA_ARGS__)\
OP(read, BLOCK_DEVICE_READ_SIG, ##__VA_ARGS__)\

struct blk_driver {
DECLARE_OP_LIST_PTRS(BLOCK_DEVICE_OP_LIST, struct blk_dev *)
};

struct blk_dev
{
    struct blk_driver *driver;

    struct stree_node blk_dev_node;
    struct vfs_node vfs_node;

    // Fixed fields
    size_t num_sectors;
    order_t sector_order;
    order_t page_order;
    size_t sectors_per_page;
};

DEFINE_OP_LIST_WRAPPERS(
        BLOCK_DEVICE_OP_LIST,
        static inline,
        /* No Prefix */,
        blk_dev,
        ->driver->,
        SELF_ACCESSOR)

#undef BLOCK_DEVICE_READ_SIG
#undef BLOCK_DEVICE_WRITE_SIG
#undef BLOCK_DEVICE_OP_LIST

/*
 * Internal API(s)
 */

// Keeps a reference to "name"
int
register_blk_dev(struct blk_dev *blk,
        const char *name,
        struct blk_driver *driver,
        size_t num_sectors,
        order_t sector_order);

int
unregister_blk_dev(struct blk_dev *blk);

struct blk_dev *
blk_dev_find(const char *name);

#endif
