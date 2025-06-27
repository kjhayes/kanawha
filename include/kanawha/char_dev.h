#ifndef __KANAWHA__CHAR_DEV_H__
#define __KANAWHA__CHAR_DEV_H__

#include <kanawha/types.h>
#include <kanawha/ops.h>
#include <kanawha/dev.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/fs/mount.h>
#include <kanawha/fs/node.h>
#include <kanawha/fs/sys/vfs.h>

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

DECLARE_DEV_TYPE(char, CHAR_DEV_OP_LIST);

#undef CHAR_DEV_OP_LIST
#undef CHAR_DEV_READ_SIG
#undef CHAR_DEV_WRITE_SIG

#endif
