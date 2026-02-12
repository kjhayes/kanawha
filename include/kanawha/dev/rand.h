#ifndef __KANAWHA__RAND_DEV_H__
#define __KANAWHA__RAND_DEV_H__

#include <kanawha/dev.h>
#include <kanawha/types.h>
#include <kanawha/ops.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/waitqueue.h>

struct rand_dev;
struct rand_driver;

#define RAND_DEV_READ_SIG(RET,ARG,...)\
RET(ssize_t)\
ARG(void *, buffer)\
ARG(size_t, amount)

#define RAND_DEV_OP_LIST(OP, ...)\
OP(read, RAND_DEV_READ_SIG, ##__VA_ARGS__)

struct rand_driver {
DECLARE_OP_LIST_PTRS(RAND_DEV_OP_LIST, struct rand_dev *);
};

struct rand_dev {
    struct dev dev;
    struct rand_driver *driver;

    struct waitqueue read_wq;
};

static inline void
rand_dev_wake_readers(
	struct rand_dev *dev)
{
    wake_all(&dev->read_wq);
}

DEFINE_OP_LIST_WRAPPERS(
        RAND_DEV_OP_LIST,
        static inline,
        /* No Prefix */,
        rand_dev,
        DRIVER_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR);

DECLARE_DEV_TYPE(rand_dev);

#undef RAND_DEV_OP_LIST
#undef RAND_DEV_READ_SIG

#endif
