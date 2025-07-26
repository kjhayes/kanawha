#ifndef __KANAWHA__CHAR_DEV_H__
#define __KANAWHA__CHAR_DEV_H__

#include <kanawha/types.h>
#include <kanawha/registry.h>
#include <kanawha/ops.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/sysfs/vfs.h>

struct char_dev;
struct char_driver;

#define CHAR_DEV_READ_SIG(RET,ARG)\
RET(size_t)\
ARG(void *, buffer)\
ARG(size_t, amount)

#define CHAR_DEV_WRITE_SIG(RET,ARG)\
RET(size_t)\
ARG(void *, buffer)\
ARG(size_t, amount)

#define CHAR_DEV_FLUSH_SIG(RET,ARG)\
RET(int)

#define CHAR_DEV_OP_LIST(OP, ...)\
OP(read, CHAR_DEV_READ_SIG, ##__VA_ARGS__)\
OP(write, CHAR_DEV_WRITE_SIG, ##__VA_ARGS__)\
OP(flush, CHAR_DEV_FLUSH_SIG, ##__VA_ARGS__)

struct char_driver {
DECLARE_OP_LIST_PTRS(CHAR_DEV_OP_LIST, struct char_dev *);
};

struct char_dev {
    struct registry_node registry_node;
    struct char_driver *driver;
};

DEFINE_OP_LIST_WRAPPERS(
        CHAR_DEV_OP_LIST,
        static inline,
        /* No Prefix */,
        char_dev,
        DRIVER_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR);

DECLARE_REGISTRY(char_dev);

#undef CHAR_DEV_OP_LIST
#undef CHAR_DEV_READ_SIG
#undef CHAR_DEV_WRITE_SIG

#endif
