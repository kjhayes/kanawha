#ifndef __KANAWHA__SND_DEV_H__
#define __KANAWHA__SND_DEV_H__

#include <kanawha/dev.h>
#include <kanawha/types.h>
#include <kanawha/ops.h>
#include <kanawha/stree.h>
#include <kanawha/ptree.h>
#include <kanawha/waitqueue.h>
#include <kanawha/uapi/snd.h>

struct snd_dev;
struct snd_driver;

#define SND_DEV_GET_MODE_INFO_SIG(RET,ARG,...)\
RET(struct snd_mode_info *)\
ARG(size_t, index)

#define SND_DEV_PUT_MODE_INFO_SIG(RET,ARG,...)\
RET(int)\
ARG(size_t, index)\
ARG(struct snd_mode_info *, info)\

#define SND_DEV_SET_MODE_SIG(RET,ARG,...)\
RET(int)\
ARG(size_t, index)

#define SND_DEV_GET_MODE_SIG(RET,ARG,...)\
RET(ssize_t)\

#define SND_DEV_WRITE_SAMPLES_NON_BLOCKING (1UL<<0)

#define SND_DEV_WRITE_SAMPLES_SIG(RET,ARG,...)\
RET(ssize_t)\
ARG(void *, buffer)\
ARG(size_t, buflen)\
ARG(unsigned long, flags)

#define SND_DEV_OP_LIST(OP, ...)\
OP(get_mode_info, SND_DEV_GET_MODE_INFO_SIG, ##__VA_ARGS__)\
OP(put_mode_info, SND_DEV_PUT_MODE_INFO_SIG, ##__VA_ARGS__)\
OP(set_mode, SND_DEV_SET_MODE_SIG, ##__VA_ARGS__)\
OP(get_mode, SND_DEV_GET_MODE_SIG, ##__VA_ARGS__)\
OP(write_samples, SND_DEV_WRITE_SAMPLES_SIG, ##__VA_ARGS__)

struct snd_driver {
DECLARE_OP_LIST_PTRS(SND_DEV_OP_LIST, struct snd_dev *);
};

struct snd_dev
{
    struct dev dev;
    struct snd_driver *driver;
};

DEFINE_OP_LIST_WRAPPERS(
        SND_DEV_OP_LIST,
        static inline,
        /* No Prefix */,
        snd_dev,
        DRIVER_STRUCT_PTR_ACCESSOR,
        SELF_ACCESSOR);

DECLARE_DEV_TYPE(snd_dev);

#undef SND_DEV_OP_LIST

#endif
