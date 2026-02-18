#ifndef __KANAWHA__BLOCK_DEVICE_H__
#define __KANAWHA__BLOCK_DEVICE_H__

#include <kanawha/dev.h>
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

#define BLOCK_DEVICE_PWRITE_SIG(RET,ARG,...)\
RET(int)\
ARG(void __phys *, data)\
ARG(size_t, base_sector)\
ARG(size_t, num_sectors)

#define BLOCK_DEVICE_PREAD_SIG(RET,ARG,...)\
RET(int)\
ARG(void __phys *, data)\
ARG(size_t, base_sector)\
ARG(size_t, num_sectors)

#define BLOCK_DEVICE_FLUSH_SIG(RET,ARG,...)\
RET(int)\
ARG(unsigned long, flags)

#define BLOCK_DEVICE_NUM_SECTORS_SIG(RET,ARG,...)\
RET(ssize_t)

#define BLOCK_DEVICE_SECTOR_ORDER_SIG(RET,ARG,...)\
RET(order_t)

#define BLOCK_DEVICE_OP_LIST(OP, ...)\
OP(write, BLOCK_DEVICE_WRITE_SIG, ##__VA_ARGS__)\
OP(read, BLOCK_DEVICE_READ_SIG, ##__VA_ARGS__)\
OP(pwrite, BLOCK_DEVICE_PWRITE_SIG, ##__VA_ARGS__)\
OP(pread, BLOCK_DEVICE_PREAD_SIG, ##__VA_ARGS__)\
OP(flush, BLOCK_DEVICE_FLUSH_SIG, ##__VA_ARGS__)\
OP(num_sectors, BLOCK_DEVICE_NUM_SECTORS_SIG, ##__VA_ARGS__)\
OP(sector_order, BLOCK_DEVICE_SECTOR_ORDER_SIG, ##__VA_ARGS__)\

struct blk_driver {
DECLARE_OP_LIST_PTRS(BLOCK_DEVICE_OP_LIST, struct blk_dev *);
};

struct blk_dev
{
    struct dev dev;
    struct blk_driver *driver;
};

// Default Implementations
int
blk_dev_write_using_pwrite(
        struct blk_dev *dev,
        void *ptr,
        size_t base_sector,
        size_t num_sectors);
int
blk_dev_read_using_pread(
        struct blk_dev *dev,
        void *ptr,
        size_t base_sector,
        size_t num_sectors);

int
blk_dev_pwrite_using_write(
        struct blk_dev *dev,
        void __phys *ptr,
        size_t base_sector,
        size_t num_sectors);
int
blk_dev_pread_using_read(
        struct blk_dev *dev,
        void __phys *ptr,
        size_t base_sector,
        size_t num_sectors);

int
blk_dev_nop_flush(
        struct blk_dev *dev,
        unsigned long flags);
//

DEFINE_OP_LIST_WRAPPERS(
        BLOCK_DEVICE_OP_LIST,
        static inline,
        /* No Prefix */,
        blk_dev,
        DRIVER_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR);

DECLARE_DEV_TYPE(blk_dev);

#undef BLOCK_DEVICE_READ_SIG
#undef BLOCK_DEVICE_WRITE_SIG
#undef BLOCK_DEVICE_OP_LIST

#endif
