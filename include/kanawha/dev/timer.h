#ifndef __KANAWHA__TIMER_DEV_H__
#define __KANAWHA__TIMER_DEV_H__

#include <kanawha/dev.h>
#include <kanawha/ops.h>
#include <kanawha/time.h>

struct timer_dev;
struct timer_driver;

typedef void(alarm_f)(void);

#define TIMER_DEV_CLEAR_ALARM_SIG(RET, ARG, ...)                               \
    RET(int)                                                                   \
    ARG(size_t, alarm)

#define TIMER_DEV_SET_ALARM_ONESHOT_SIG(RET, ARG, ...)                         \
    RET(int)                                                                   \
    ARG(size_t, alarm)                                                         \
    ARG(duration_t, wait_for)                                                  \
    ARG(alarm_f *, func)

#define TIMER_DEV_SET_ALARM_PERIODIC_SIG(RET, ARG, ...)                        \
    RET(int)                                                                   \
    ARG(size_t, alarm)                                                         \
    ARG(duration_t, period)                                                    \
    ARG(alarm_f *, func)

#define TIMER_DEV_GET_ALARM_SIG(RET, ARG, ...)                                 \
    RET(int)                                                                   \
    ARG(size_t, alarm)                                                         \
    ARG(duration_t *, remaining)

#define TIMER_DEV_OP_LIST(OP, ...)                                             \
    OP(clear_alarm, TIMER_DEV_CLEAR_ALARM_SIG, ##__VA_ARGS__)                  \
    OP(set_alarm_oneshot, TIMER_DEV_SET_ALARM_ONESHOT_SIG, ##__VA_ARGS__)      \
    OP(set_alarm_periodic, TIMER_DEV_SET_ALARM_PERIODIC_SIG, ##__VA_ARGS__)    \
    OP(get_alarm, TIMER_DEV_GET_ALARM_SIG, ##__VA_ARGS__)

struct timer_driver
{
    DECLARE_OP_LIST_PTRS(TIMER_DEV_OP_LIST, struct timer_dev *)
};

struct timer_dev
{
    struct dev dev;
    struct timer_driver *driver;
    size_t alarm_count;
};

DEFINE_OP_LIST_WRAPPERS(TIMER_DEV_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        timer_dev,
                        DRIVER_STRUCT_PTR_ACCESSOR,
                        SELF_ACCESSOR)

DECLARE_DEV_TYPE(timer_dev);

#undef TIMER_DEV_SET_ALARM_SIG
#undef TIMER_DEV_OP_LIST

#endif
