#ifndef __KANAWHA__TIMER_H__
#define __KANAWHA__TIMER_H__

#include <kanawha/time.h>
#include <kanawha/timer_dev.h>

struct timer;

// Provide a timer which can be used by
// the rest of the kernel as needed
int
provide_timer(struct timer_dev *dev, size_t alarm);

// Try to take a timer back from the kernel
// (This might fail)
int
retract_timer(struct timer_dev *dev, size_t alarm);

// Ask for exclusive access to a timer
struct timer *
reserve_timer(void);
// Give back exclusive access to a timer
int
return_timer(struct timer *timer);

int
timer_clear(struct timer *timer);

int
timer_set_periodic(
        struct timer *timer,
        duration_t period,
        alarm_f *callback);

int
timer_set_oneshot(
        struct timer *timer,
        duration_t wait_for,
        alarm_f *callback);

#endif
