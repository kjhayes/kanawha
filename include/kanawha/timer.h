#ifndef __KANAWHA__TIMER_H__
#define __KANAWHA__TIMER_H__

#include <kanawha/time.h>
#include <kanawha/timer_dev.h>

typedef void(timer_callback_f)(void *state);

int
timer_set_oneshot(
        duration_t wait_for,
        timer_callback_f *callback,
        void *state);

struct timer_event *
timer_set_periodic(
        duration_t period,
        timer_callback_f *callback,
        void *state);

int
timer_source_set(struct timer_dev *dev, size_t alarm);

struct timer_dev *
timer_source_get_dev(void);
size_t
timer_source_get_alarm(void);

#endif
