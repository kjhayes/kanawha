#ifndef __KANAWHA__FB_DEV_H__
#define __KANAWHA__FB_DEV_H__

#include <kanawha/types.h>
#include <kanawha/ops.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/sys/vfs.h>
#include <kanawha/uapi/fb.h>

struct fb_dev;
struct fb_driver;
struct fb_mode_info;

// Device Ops

#define FB_DEV_GET_MODE_INFO_SIG(RET,ARG)\
RET(struct fb_mode_info *)\
ARG(size_t, index)

#define FB_DEV_PUT_MODE_INFO_SIG(RET,ARG)\
RET(int)\
ARG(size_t, index)

#define FB_DEV_SET_MODE_SIG(RET,ARG)\
RET(int)\
ARG(size_t, index)

#define FB_DEV_GET_MODE_SIG(RET,ARG)\
RET(ssize_t)

// The provided buffer should be accessible as if it were regular RAM
// It should also be VMEM_MIN_PAGE_ORDER aligned, but does not need to
// be a multiple of the page size
#define FB_DEV_LOAD_BUFFER_SIG(RET,ARG)\
RET(int)\
ARG(void __phys **, base_out)

#define FB_DEV_UNLOAD_BUFFER_SIG(RET,ARG)\
RET(int)\
ARG(void __phys *, base)

#define FB_DEV_FLUSH_BUFFER_SIG(RET,ARG)\
RET(int)

#define FB_DEV_OP_LIST(OP, ...)\
OP(get_mode_info, FB_DEV_GET_MODE_INFO_SIG, ##__VA_ARGS__)\
OP(put_mode_info, FB_DEV_PUT_MODE_INFO_SIG, ##__VA_ARGS__)\
OP(set_mode, FB_DEV_SET_MODE_SIG, ##__VA_ARGS__)\
OP(get_mode, FB_DEV_GET_MODE_SIG, ##__VA_ARGS__)\
OP(load_buffer, FB_DEV_LOAD_BUFFER_SIG, ##__VA_ARGS__)\
OP(unload_buffer, FB_DEV_UNLOAD_BUFFER_SIG, ##__VA_ARGS__)\
OP(flush_buffer, FB_DEV_FLUSH_BUFFER_SIG, ##__VA_ARGS__)\

struct fb_driver {
DECLARE_OP_LIST_PTRS(FB_DEV_OP_LIST, struct fb_dev *);
};

struct fb_dev {
    struct fb_driver *driver;
    struct stree_node fb_dev_node;

    spinlock_t buffer_lock;
    size_t buffer_mode;
    struct fb_mode_info *buffer_info;
    size_t buffer_pages_loaded;
    void __phys *buffer_addr;
    void __phys *buffer_tail_page;
    ssize_t buffer_tail_pfn;

    struct vfs_node buffer_vfs_node;
    struct vfs_node mode_set_vfs_node;
    struct vfs_node mode_info_vfs_node;
    size_t mode_info_vfs_current_mode;
};

DEFINE_OP_LIST_WRAPPERS(
        FB_DEV_OP_LIST,
        static inline,
        /* No Prefix */,
        fb_dev,
        ->driver->,
        SELF_ACCESSOR);

#undef FB_DEV_OP_LIST
#undef FB_DEV_GET_MODE_INFO_SIG
#undef FB_DEV_PUT_MODE_INFO_SIG
#undef FB_DEV_SET_MODE_SIG
#undef FB_DEV_LOAD_LAYER_SIG
#undef FB_DEV_UNLOAD_LAYER_SIG

int
register_fb_dev(
        struct fb_dev *dev,
        const char *name,
        struct fb_driver *driver);
int
unregister_fb_dev(
        struct fb_dev *dev);

struct fs_mount *
fb_dev_get_mount(void);

struct fb_dev *
fb_dev_find(const char *name);

#endif
