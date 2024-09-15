#ifndef __KANAWHA__BLOCK_DEVICE_H__
#define __KANAWHA__BLOCK_DEVICE_H__

#include <kanawha/stdint.h>
#include <kanawha/ops.h>
#include <kanawha/list.h>
#include <kanawha/atomic.h>
#include <kanawha/ptree.h>
#include <kanawha/stree.h>

#define MIN_BLOCK_DEVICE_PAGE_ORDER 12

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
ARG(size_t, disk_index)\
ARG(size_t *, num_sec)

#define BLOCK_DEVICE_OP_LIST(OP, ...)\
OP(request, BLOCK_DEVICE_REQUEST_SIG, ##__VA_ARGS__)\
OP(num_sectors, BLOCK_DEVICE_NUM_SECTORS_SIG, ##__VA_ARGS__)

struct blk_driver {
DECLARE_OP_LIST_PTRS(BLOCK_DEVICE_OP_LIST, struct blk_dev *)
};

struct blk_dev_disk;

struct blk_dev
{
    struct blk_driver *driver;
    struct device *device;

    struct stree_node blk_dev_node;

    order_t sector_order; // Order of a sector on the disk
    size_t num_disks;

    struct blk_dev_disk *disks;
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
 * External Cached API
 */

static inline order_t
blk_dev_sector_order(
        struct blk_dev *dev)
{
    return dev->sector_order;
}

struct cached_page *
blk_dev_get_sector(
        struct blk_dev *dev,
        size_t disk,
        size_t sector);

int
blk_dev_put_sector(
        struct cached_page *page);

// Read/Write Functions Using Cached Pages
//
// returns 0 on success, if less is read or
// written than expected, len is modified to
// indicate the amount actually read or written
int
blk_dev_read(
        struct blk_dev *dev,
        size_t disk_index,
        void *buffer,
        size_t offset,
        size_t *len);

int
blk_dev_write(
        struct blk_dev *dev,
        size_t disk_index,
        void *buffer,
        size_t offset,
        size_t *len);

/*
 * Internal API(s)
 */

// Keeps a reference to "name"
int
register_blk_dev(struct blk_dev *blk,
        const char *name,
        struct blk_driver *driver,
        struct device *device,
        order_t sector_order,
        size_t num_disks);

int
unregister_blk_dev(struct blk_dev *blk);

struct blk_dev *
blk_dev_find(const char *name);

/*
 * Blocking Direct Read/Write Function
 */
int
blk_dev_read_direct(
        struct blk_dev *dev,
        size_t disk_index,
        void *buffer,
        size_t base_sector,
        size_t num_sectors);

int
blk_dev_write_direct(
        struct blk_dev *dev,
        size_t disk_index,
        void *buffer,
        size_t base_sector,
        size_t num_sectors);

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
