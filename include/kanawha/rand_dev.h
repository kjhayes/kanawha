#ifndef __KANAWHA__RAND_DEV_H__
#define __KANAWHA__RAND_DEV_H__

#include <kanawha/types.h>
#include <kanawha/ops.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/fs/sys/vfs.h>

struct rand_dev;
struct rand_driver;

#define RAND_DEV_READ_SIG(RET,ARG)\
RET(ssize_t)\
ARG(void *, buffer)\
ARG(size_t, amount)

#define RAND_DEV_OP_LIST(OP, ...)\
OP(read, RAND_DEV_READ_SIG, ##__VA_ARGS__)

struct rand_driver {
DECLARE_OP_LIST_PTRS(RAND_DEV_OP_LIST, struct rand_dev*)
};

struct rand_dev {
    struct rand_driver *driver;
    struct stree_node rand_dev_node;

    struct vfs_node vfs_node;
};

DEFINE_OP_LIST_WRAPPERS(
        RAND_DEV_OP_LIST,
        static inline,
        /* No Prefix */,
        rand_dev,
        ->driver->,
        SELF_ACCESSOR);

#undef RAND_DEV_OP_LIST
#undef RAND_DEV_READ_SIG

int
register_rand_dev(
        struct rand_dev *dev,
        const char *name,
        struct rand_driver *driver);
int
unregister_rand_dev(
        struct rand_dev *dev);

#endif
