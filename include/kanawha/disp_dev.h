#ifndef __KANAWHA__DISPLAY_DEVICE_H__
#define __KANAWHA__DISPLAY_DEVICE_H__

#include <kanawha/ops.h>
#include <kanawha/stdint.h>
#include <kanawha/stree.h>

struct disp_dev;
struct disp_mode;
struct disp_mode_info;


#define DISP_DEV_MODE_INFO_SIG(RET,ARG)\
RET(int)\
ARG(size_t, mode)\
ARG(struct disp_mode_info *, info)

#define DISP_DEV_SET_MODE_SIG(RET,ARG)\
RET(int)\
ARG(size_t, mode)

#define DISP_DEV_OP_LIST(OP, ...)\
OP(mode_info, DISP_DEV_MODE_INFO_SIG, ##__VA_ARGS__)\
OP(set_mode, DISP_DEV_SET_MODE_SIG, ##__VA_ARGS__)\

struct disp_driver {
DECLARE_OP_LIST_PTRS(DISP_DEV_OP_LIST, struct disp_dev *)
};

struct disp_dev
{
    struct disp_driver *driver;
    struct device *device;

    struct stree_node disp_dev_node;

    size_t num_modes;
};

typedef enum {
    DISP_MODE_CLASS_TEXT,
    DISP_MODE_CLASS_GRAPHIC,
} disp_mode_class_t;

struct disp_mode_info {
    size_t res_x, res_y;
    disp_mode_class_t class;
};

DEFINE_OP_LIST_WRAPPERS(
        DISP_DEV_OP_LIST,
        static inline,
        /* No Prefix */,
        disp_dev,
        ->driver->,
        SELF_ACCESSOR)

#undef DISP_DEV_MODE_INFO_SIG
#undef DISP_DEV_OP_LIST

#endif
