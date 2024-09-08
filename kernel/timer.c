
#include <kanawha/timer.h>
#include <kanawha/time.h>
#include <kanawha/timer_dev.h>
#include <kanawha/list.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/stddef.h>
#include <kanawha/irq.h>

static DECLARE_SPINLOCK(timer_event_lock);
static DECLARE_ILIST(timer_event_queue);

static struct timer_dev *timer_source_dev = NULL;
static size_t timer_source_alarm = 0;

struct timer_event
{
    duration_t time_after;

    duration_t period;

    timer_callback_f *callback;
    void *state;

    ilist_node_t event_queue_node;
};

static int
queue_timer_event(duration_t, struct timer_event *);

static void
timer_event_handler(void) {
    int irq_state = spin_lock_irq_save(&timer_event_lock);

    int res = timer_dev_clear_alarm(timer_source_dev, timer_source_alarm);
    if(res) {
        eprintk("timer_event_handler failed to clear timer source alarm! (err=%s)\n",
                errnostr(res));
    }

    ilist_node_t *node = ilist_pop_head(&timer_event_queue);
    if(node == NULL) {
        spin_unlock_irq_restore(&timer_event_lock, irq_state);
        eprintk("Warning: Spurrious Timer Event!\n");
        return;
    }
    struct timer_event *event =
        container_of(node, struct timer_event, event_queue_node);

    (*event->callback)(event->state);

    if(!ilist_empty(&timer_event_queue)) {
        ilist_node_t *next_node = timer_event_queue.next;
        struct timer_event *next_event =
            container_of(next_node, struct timer_event, event_queue_node);
        int res = timer_dev_set_alarm_oneshot(
                timer_source_dev,
                timer_source_alarm,
                next_event->time_after,
                timer_event_handler);
        if(res) {
            eprintk("Failed to set timer source alarm!\n");
        }
    }

    spin_unlock_irq_restore(&timer_event_lock, irq_state);


    if(event->period > 0) {
        int res = queue_timer_event(event->period, event);
        if(res) {
            eprintk("Failed to re-enqueue periodic timer event!\n");
        }
    } else {
        kfree(event);
    }
}

static int
queue_timer_event(
        duration_t wait_for,
        struct timer_event *event)
{
    if(timer_source_dev == NULL) {
        return -ENODEV;
    }

    int res = 0;
    int irq_state = spin_lock_irq_save(&timer_event_lock);

    res = timer_dev_clear_alarm(timer_source_dev, timer_source_alarm);
    if(res) {
        eprintk("Warning: Failed to clear timer source alarm when queuing new timer event! (err=%s)\n",
                errnostr(res));
    }

    duration_t acc_time = 0;
    int inserted = 0;

    event->time_after = wait_for;

    ilist_node_t *node;
    ilist_for_each(node, &timer_event_queue) {
        struct timer_event *queued =
            container_of(node, struct timer_event, event_queue_node);


        acc_time += queued->time_after;

        if(acc_time > wait_for) {

            if(queued->time_after < event->time_after) {
                panic("Timer queue has been corrupted!\n");
            }

            ilist_insert_before(&timer_event_queue, node, &event->event_queue_node);
            queued->time_after -= event->time_after;

            inserted = 1;
            break;
        } 

        event->time_after -= queued->time_after;
    }

    if(!inserted) {
        ilist_push_tail(&timer_event_queue, &event->event_queue_node);
    }

    // Restart the alarm
    ilist_node_t *first_node = timer_event_queue.next;
    if(first_node == NULL) {
        panic("Timer alarm queue is empty after queue_timer_event!\n");
    }

    struct timer_event *first_event =
        container_of(first_node, struct timer_event, event_queue_node);

    res = timer_dev_set_alarm_oneshot(
            timer_source_dev,
            timer_source_alarm,
            first_event->time_after,
            timer_event_handler);
    if(res) {
        eprintk("Failed to set timer source alarm!\n");
    }

    spin_unlock_irq_restore(&timer_event_lock, irq_state);
    return res;
}

int
timer_set_oneshot(
        duration_t wait_for,
        timer_callback_f *callback,
        void *state)
{
    struct timer_event *event =
        kmalloc(sizeof(struct timer_event));
    if(event == NULL) {
        return -ENOMEM;
    }
    memset(event, 0, sizeof(struct timer_event));

    event->callback = callback;
    event->state = state;
    event->period = 0; // non-periodic

    int res = queue_timer_event(wait_for, event);
    if(res) {
        kfree(event);
        return res;
    }

    return 0;
}

struct timer_event *
timer_set_periodic(
        duration_t period,
        timer_callback_f *callback,
        void *state)
{
    struct timer_event *event =
        kmalloc(sizeof(struct timer_event));
    if(event == NULL) {
        return NULL;
    }
    memset(event, 0, sizeof(struct timer_event));

    event->callback = callback;
    event->state = state;
    event->period = period; // non-periodic

    int res = queue_timer_event(period, event);
    if(res) {
        kfree(event);
        return NULL;
    }

    return event;
}

int
timer_source_set(struct timer_dev *dev, size_t alarm) 
{
    int irq = spin_lock_irq_save(&timer_event_lock);
    timer_source_alarm = alarm;
    timer_source_dev = dev;
    spin_unlock_irq_restore(&timer_event_lock, irq);
    return 0;
}

struct timer_dev *
timer_source_get_dev(void) 
{
    return timer_source_dev;
}

size_t
timer_source_get_alarm(void) 
{
    return timer_source_alarm;
}

