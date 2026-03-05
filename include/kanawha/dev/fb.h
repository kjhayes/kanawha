#ifndef __KANAWHA__FB_DEV_H__
#define __KANAWHA__FB_DEV_H__

#include <kanawha/dev.h>
#include <kanawha/fs/mount.h>
#include <kanawha/ops.h>
#include <kanawha/types.h>
#include <kanawha/uapi/fb.h>

struct fb_mode_info;

struct fb_dev;
struct fb_driver;

// Device Ops

#define FB_DEV_GET_MODE_INFO_SIG(RET, ARG, ...)                                \
    RET(struct fb_mode_info *)                                                 \
    ARG(size_t, index)

#define FB_DEV_PUT_MODE_INFO_SIG(RET, ARG, ...)                                \
    RET(int)                                                                   \
    ARG(size_t, index)

#define FB_DEV_SET_MODE_SIG(RET, ARG, ...)                                     \
    RET(int)                                                                   \
    ARG(size_t, index)

#define FB_DEV_GET_MODE_SIG(RET, ARG, ...) RET(ssize_t)

// The provided buffer should be accessible as if it were regular RAM
// It should also be VMEM_MIN_PAGE_ORDER aligned, but does not need to
// be a multiple of the page size
#define FB_DEV_LOAD_BUFFER_SIG(RET, ARG, ...)                                  \
    RET(int)                                                                   \
    ARG(void __phys **, base_out)

#define FB_DEV_UNLOAD_BUFFER_SIG(RET, ARG, ...)                                \
    RET(int)                                                                   \
    ARG(void __phys *, base)

#define FB_DEV_FLUSH_BUFFER_SIG(RET, ARG, ...) RET(int)

#define FB_DEV_OP_LIST(OP, ...)                                                \
    OP(get_mode_info, FB_DEV_GET_MODE_INFO_SIG, ##__VA_ARGS__)                 \
    OP(put_mode_info, FB_DEV_PUT_MODE_INFO_SIG, ##__VA_ARGS__)                 \
    OP(set_mode, FB_DEV_SET_MODE_SIG, ##__VA_ARGS__)                           \
    OP(get_mode, FB_DEV_GET_MODE_SIG, ##__VA_ARGS__)                           \
    OP(load_buffer, FB_DEV_LOAD_BUFFER_SIG, ##__VA_ARGS__)                     \
    OP(unload_buffer, FB_DEV_UNLOAD_BUFFER_SIG, ##__VA_ARGS__)                 \
    OP(flush_buffer, FB_DEV_FLUSH_BUFFER_SIG, ##__VA_ARGS__)

struct fb_driver
{
    DECLARE_OP_LIST_PTRS(FB_DEV_OP_LIST, struct fb_dev *);
};

struct fb_dev
{
    struct dev dev;
    struct fb_driver *driver;
};

DEFINE_OP_LIST_WRAPPERS(FB_DEV_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        fb_dev,
                        DRIVER_STRUCT_PTR_ACCESSOR,
                        SELF_ACCESSOR);

DECLARE_DEV_TYPE(fb_dev);

#undef FB_DEV_OP_LIST
#undef FB_DEV_GET_MODE_INFO_SIG
#undef FB_DEV_PUT_MODE_INFO_SIG
#undef FB_DEV_SET_MODE_SIG
#undef FB_DEV_LOAD_LAYER_SIG
#undef FB_DEV_UNLOAD_LAYER_SIG

#endif
