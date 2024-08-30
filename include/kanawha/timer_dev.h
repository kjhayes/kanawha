#ifndef __KANAWHA__TIMER_DEV_H__
#define __KANAWHA__TIMER_DEV_H__

#include <kanawha/time.h>
#include <kanawha/ops.h>

struct timer_dev;
struct timer_driver;

typedef void(alarm_f)(void);

#define TIMER_DEV_CLEAR_ALARM_SIG(RET,ARG)\
RET(int)\
ARG(size_t, alarm)

#define TIMER_DEV_SET_ALARM_ONESHOT_SIG(RET,ARG)\
RET(int)\
ARG(size_t, alarm)\
ARG(duration_t, wait_for)\
ARG(alarm_f *, func)

#define TIMER_DEV_SET_ALARM_PERIODIC_SIG(RET,ARG)\
RET(int)\
ARG(size_t, alarm)\
ARG(duration_t, period)\
ARG(alarm_f *, func)

#define TIMER_DEV_OP_LIST(OP,...)\
OP(clear_alarm, TIMER_DEV_CLEAR_ALARM_SIG, ##__VA_ARGS__)\
OP(set_alarm_oneshot, TIMER_DEV_SET_ALARM_ONESHOT_SIG, ##__VA_ARGS__)\
OP(set_alarm_periodic, TIMER_DEV_SET_ALARM_PERIODIC_SIG, ##__VA_ARGS__)

struct timer_driver {
DECLARE_OP_LIST_PTRS(TIMER_DEV_OP_LIST, struct timer_dev*)
};

struct timer_dev
{
    struct timer_driver *driver;
    struct device *device;

    size_t alarm_count;
};

DEFINE_OP_LIST_WRAPPERS(
        TIMER_DEV_OP_LIST,
        static inline,
        /* No Prefix */,
        timer_dev,
        ->driver->,
        SELF_ACCESSOR)

#undef TIMER_DEV_SET_ALARM_SIG
#undef TIMER_DEV_OP_LIST

#endif
