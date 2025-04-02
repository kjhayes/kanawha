#ifndef __KANAWHA__DRIVER_FB_VIRTIO_GPU_H__
#define __KANAWHA__DRIVER_FB_VIRTIO_GPU_H__

#include <kanawha/endian.h>
#include <kanawha/types.h>
#include <kanawha/fb_dev.h>
#include <drivers/virtio/queue.h>
#include <drivers/virtio/device.h>

#define VIRTIO_GPU_EVENT_DISPLAY (1 << 0)

struct virtio_gpu_config
{
    le32_t events_read;
    le32_t events_clear;
    le32_t num_scanouts;
    le32_t num_capsets;
};

enum virtio_gpu_ctrl_type
{
    /* 2d commands */
    VIRTIO_GPU_CMD_GET_DISPLAY_INFO = 0x0100,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
    VIRTIO_GPU_CMD_RESOURCE_UNREF,
    VIRTIO_GPU_CMD_SET_SCANOUT,
    VIRTIO_GPU_CMD_RESOURCE_FLUSH,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
    VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
    VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
    VIRTIO_GPU_CMD_GET_CAPSET_INFO,
    VIRTIO_GPU_CMD_GET_CAPSET,
    VIRTIO_GPU_CMD_GET_EDID,
    VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB,
    VIRTIO_GPU_CMD_SET_SCANOUT_BLOB,
    /* 3d commands */
    VIRTIO_GPU_CMD_CTX_CREATE = 0x0200,
    VIRTIO_GPU_CMD_CTX_DESTROY,
    VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE,
    VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_3D,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D,
    VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D,
    VIRTIO_GPU_CMD_SUBMIT_3D,
    VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB,
    VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB,
    /* cursor commands */
    VIRTIO_GPU_CMD_UPDATE_CURSOR = 0x0300,
    VIRTIO_GPU_CMD_MOVE_CURSOR,
    /* success responses */
    VIRTIO_GPU_RESP_OK_NODATA = 0x1100,
    VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
    VIRTIO_GPU_RESP_OK_CAPSET_INFO,
    VIRTIO_GPU_RESP_OK_CAPSET,
    VIRTIO_GPU_RESP_OK_EDID,
    VIRTIO_GPU_RESP_OK_RESOURCE_UUID,
    VIRTIO_GPU_RESP_OK_MAP_INFO,
    /* error responses */
    VIRTIO_GPU_RESP_ERR_UNSPEC = 0x1200,
    VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
    VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID,
    VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
};

#define VIRTIO_GPU_FLAG_FENCE (1 << 0)
#define VIRTIO_GPU_FLAG_INFO_RING_IDX (1 << 1)

struct virtio_gpu_ctrl_hdr
{
  le32_t type;
  le32_t flags;
  le64_t fence_id;
  le32_t ctx_id;
  uint8_t ring_idx;
  uint8_t padding[3];
};

#define VIRTIO_GPU_MAX_SCANOUTS 16

struct virtio_gpu_rect {
  le32_t x;
  le32_t y;
  le32_t width;
  le32_t height;
};

struct virtio_gpu_resp_display_info {
  struct virtio_gpu_ctrl_hdr hdr;
  struct virtio_gpu_display_one {
    struct virtio_gpu_rect r;
    le32_t enabled;
    le32_t flags;
  } pmodes[VIRTIO_GPU_MAX_SCANOUTS];
};

enum virtio_gpu_formats {
    VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM = 1,
    VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM = 2,
    VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM = 3,
    VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM = 4,
    VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM = 67,
    VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM = 68,
    VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM = 121,
    VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM = 134,
};

struct virtio_gpu_resource_create_2d
{
    struct virtio_gpu_ctrl_hdr hdr;
    le32_t resource_id;
    le32_t format;
    le32_t width;
    le32_t height;
};

struct virtio_gpu_resource_unref
{
    struct virtio_gpu_ctrl_hdr hdr;
    le32_t resource_id;
    le32_t padding;
};

struct virtio_gpu_resource_attach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    le32_t resource_id;
    le32_t nr_entries;
};

struct virtio_gpu_mem_entry
{
    le64_t addr;
    le32_t length;
    le32_t padding;
};

struct virtio_gpu_resource_detach_backing
{
    struct virtio_gpu_ctrl_hdr hdr;
    le32_t resource_id;
    le32_t padding;
};

struct virtio_gpu_resource_flush
{
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    le32_t resource_id;
    le32_t padding;
};

struct virtio_gpu_transfer_to_host_2d
{
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    le64_t offset;
    le32_t resource_id;
    le32_t padding;
};

struct virtio_gpu_set_scanout
{
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    le32_t scanout_id;
    le32_t resource_id;
};

//
struct virtio_gpu_scanout {
    uint32_t pref_width;
    uint32_t pref_height;
    uint32_t pref_pos_x;
    uint32_t pref_pos_y;
    int enabled;
};

struct virtio_gpu_resource
{
    struct ptree_node tree_node;

    enum virtio_gpu_resource_type {
        VIRTIO_GPU_RESOURCE_TYPE_2D,
        VIRTIO_GPU_RESOURCE_TYPE_BLOB,
    } type;

    int id;
    size_t width;
    size_t height;

    struct virtio_gpu *gpu;
};

struct virtio_gpu
{
    struct fb_dev fb_dev;
    char *name;
    struct virtio_queue *control_queue;
    struct virtio_queue *cursor_queue;

    size_t num_scanouts;
    size_t num_enabled_scanouts;
    struct virtio_gpu_scanout *scanouts;

    spinlock_t resource_lock;
    struct ptree resource_tree;

    size_t current_mode;
    size_t current_buffer_size;
    dma_addr_t current_buffer;
    struct virtio_gpu_resource *current_res;
};

int
virtio_gpu_update_scanout_info(
        struct virtio_gpu *gpu);

struct virtio_gpu_resource *
virtio_gpu_create_resource_2d(
        struct virtio_gpu *gpu,
        size_t width,
        size_t height,
        enum virtio_gpu_formats format);

int
virtio_gpu_destroy_resource_2d(
        struct virtio_gpu_resource *resource);
int
virtio_gpu_resource_attach_backing(
        struct virtio_gpu_resource *resource,
        void __phys *backing_data,
        size_t backing_size);

int
virtio_gpu_resource_deattach_backing(
        struct virtio_gpu_resource *resource);

int
virtio_gpu_resource_transfer_to_host(
        struct virtio_gpu_resource *resource);

int
virtio_gpu_resource_flush(
        struct virtio_gpu_resource *resource);

int
virtio_gpu_set_scanout(
        struct virtio_gpu *gpu,
        int scanout_index,
        size_t width,
        size_t height,
        struct virtio_gpu_resource *resource);

#endif
