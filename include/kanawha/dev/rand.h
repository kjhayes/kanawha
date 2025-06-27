#ifndef __KANAWHA__RAND_DEV_H__
#define __KANAWHA__RAND_DEV_H__

#include <kanawha/dev.h>
#include <kanawha/types.h>
#include <kanawha/ops.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/fs/sys/vfs.h>

#define RAND_DEV_READ_SIG(RET,ARG)\
RET(ssize_t)\
ARG(void *, buffer)\
ARG(size_t, amount)

#define RAND_DEV_OP_LIST(OP, ...)\
OP(read, RAND_DEV_READ_SIG, ##__VA_ARGS__)

DECLARE_DEV_TYPE(rand, RAND_DEV_OP_LIST);

#undef RAND_DEV_OP_LIST
#undef RAND_DEV_READ_SIG

#endif
