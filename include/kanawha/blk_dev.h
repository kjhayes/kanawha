#ifndef __KANAWHA__BLOCK_DEVICE_H__
#define __KANAWHA__BLOCK_DEVICE_H__

#include <kanawha/types.h>
#include <kanawha/ops.h>
#include <kanawha/list.h>
#include <kanawha/atomic.h>
#include <kanawha/ptree.h>
#include <kanawha/stree.h>
#include <kanawha/fs/flat.h>

struct blk_dev;
struct blk_driver;
struct blk_dev_request;

// Submit a synchronous request to the block device
#define BLOCK_DEVICE_REQUEST_SIG(RET,ARG)\
RET(int)\
ARG(struct blk_dev_request *, req)

// Get the total size of the disk in sectors
#define BLOCK_DEVICE_NUM_SECTORS_SIG(RET,ARG)\
RET(int)\
ARG(size_t *, num_sec)

#define BLOCK_DEVICE_OP_LIST(OP, ...)\
OP(request, BLOCK_DEVICE_REQUEST_SIG, ##__VA_ARGS__)\
OP(num_sectors, BLOCK_DEVICE_NUM_SECTORS_SIG, ##__VA_ARGS__)

struct blk_driver {
DECLARE_OP_LIST_PTRS(BLOCK_DEVICE_OP_LIST, struct blk_dev *)
};

struct blk_dev
{
    struct blk_driver *driver;

    struct stree_node blk_dev_node;
    struct flat_node flat_fs_node;
};

DEFINE_OP_LIST_WRAPPERS(
        BLOCK_DEVICE_OP_LIST,
        static inline,
        /* No Prefix */,
        blk_dev,
        ->driver->,
        SELF_ACCESSOR)

#undef BLOCK_DEVICE_REQUEST_SIG
#undef BLOCK_DEVICE_NUM_SECTORS_SIG
#undef BLOCK_DEVICE_SECTOR_INFO_SIG
#undef BLOCK_DEVICE_OP_LIST

/*
 * Internal API(s)
 */

// Keeps a reference to "name"
int
register_blk_dev(struct blk_dev *blk,
        const char *name,
        struct blk_driver *driver);

int
unregister_blk_dev(struct blk_dev *blk);

struct blk_dev *
blk_dev_find(const char *name);

// blk_dev request API
struct blk_dev_request {
    // blk_dev Driver API
    enum blk_dev_request_type {
        BLK_DEV_REQ_READ,
        BLK_DEV_REQ_WRITE,
    } type;

    // every request will be sent to a specific disk
    size_t disk;

    union
    {
        struct {
            void *buffer_to;
            size_t sector_from;
            size_t num_sectors; // Size of the buffer in sectors
        } read_input;

        struct {
            size_t sectors_read;
        } read_output;

        struct {
            void *buffer_from;
            size_t sector_to;
            size_t num_sectors;
        } write_input;

        struct {
            size_t sectors_written;
        } write_output;
    };

    // blk_dev Framework Internal
    atomic_bool_t complete;
};

#endif
