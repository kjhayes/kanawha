
#include <kanawha/timer.h>
#include <kanawha/time.h>
#include <kanawha/timer_dev.h>
#include <kanawha/list.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/irq.h>

static DECLARE_SPINLOCK(timers_lock);
static DECLARE_ILIST(available_timers);
static DECLARE_ILIST(reserved_timers);

struct timer
{
    struct timer_dev *dev;
    size_t alarm;

    ilist_node_t list_node;
};

int
provide_timer(struct timer_dev *dev, size_t alarm)
{
    struct timer *timer = kmalloc(sizeof(struct timer));
    if(timer == NULL) {
        return -ENOMEM;
    }
    memset(timer, 0, sizeof(struct timer));

    timer->dev = dev;
    timer->alarm = alarm;

    int flags = spin_lock_irq_save(&timers_lock);
    ilist_push_tail(&available_timers, &timer->list_node);
    spin_unlock_irq_restore(&timers_lock, flags);
    return 0;
}

int
retract_timer(struct timer_dev *dev, size_t alarm)
{
    // We're gonna be lazy for now and just say "No"
    // regardless of if it's being used or not.
    return -EINVAL;
}

struct timer *
reserve_timer(void)
{
    int flags = spin_lock_irq_save(&timers_lock);
    ilist_node_t *node =
        ilist_pop_head(&available_timers);
    if(node == NULL) {
        spin_unlock_irq_restore(&timers_lock, flags);
        return NULL;
    }
    struct timer *timer =
        container_of(node, struct timer, list_node);
    ilist_push_tail(&reserved_timers, node);
    spin_unlock_irq_restore(&timers_lock, flags);
    return timer;
}

int
return_timer(struct timer *timer)
{
    int flags = spin_lock_irq_save(&timers_lock);
    ilist_remove(&reserved_timers, &timer->list_node);
    ilist_push_tail(&available_timers, &timer->list_node);
    spin_unlock_irq_restore(&timers_lock, flags);
    return 0;
}

int
timer_clear(struct timer *timer)
{
    return timer_dev_clear_alarm(timer->dev, timer->alarm);
}

int
timer_set_periodic(
        struct timer *timer,
        duration_t period,
        alarm_f *callback)
{
    return timer_dev_set_alarm_periodic(
            timer->dev,
            timer->alarm,
            period,
            callback);
}

int
timer_set_oneshot(
        struct timer *timer,
        duration_t wait_for,
        alarm_f *callback)
{
    return timer_dev_set_alarm_oneshot(
            timer->dev,
            timer->alarm,
            wait_for,
            callback);
}


