
#include <kanawha/event.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/list.h>
#include <kanawha/irq.h>
#include <kanawha/lock.h>
#include <kanawha/types.h>
#include <kanawha/timer.h>
#include <kanawha/timer_dev.h>
#include <kanawha/stddef.h>

static size_t num_enabled_periodic_events = 0;
static DECLARE_ILIST(periodic_event_list);
DEFINE_LOCAL_IRQ_LOCK(periodic_event_list_lock);

static struct timer *periodic_timer = NULL;

static duration_t tick_length;

struct periodic_event
{
    duration_t period;
    duration_t current_period;

    ilist_node_t list_node;

    void *state;
    periodic_callback_f *callback;
};

static void
periodic_callback(void)
{
    periodic_event_list_lock_acquire();
    ilist_node_t *node;
    ilist_for_each(node, &periodic_event_list) {
        struct periodic_event *event =
            container_of(node, struct periodic_event, list_node);
        if(event->current_period <= tick_length)
        {
            event->current_period = event->period;
            // Run the event callback
            (*event->callback)(event->state);
        }
        else {
            event->current_period -= tick_length;
        }
    }
    periodic_event_list_lock_release();
}

static int
periodic_kickstart_lockless(void)
{
    int res;

    if(periodic_timer == NULL) {
        periodic_timer = reserve_timer();
    } else {
        return -EALREADY;
    }
    if(periodic_timer == NULL) {
        return -ENODEV;
    }

    tick_length = msec_to_duration(CONFIG_PERIODIC_RESOLUTION_MS); 

    res = timer_set_periodic(
            periodic_timer,
            tick_length,
            periodic_callback);
    if(res) {
        return res;
    }

    return 0;
}

static int
periodic_stop_lockless(void) {
    return -EUNIMPL;
}

static inline int
enable_periodic_event(
        struct periodic_event *event)
{
    int res;
    periodic_event_list_lock_acquire();
    ilist_push_tail(&periodic_event_list, &event->list_node);
    num_enabled_periodic_events++;
    if(num_enabled_periodic_events == 1) {
        // We need to kickstart the periodic timer
        res = periodic_kickstart_lockless();
        if(res) {
            periodic_event_list_lock_release();
            return res;
        }
    }
    periodic_event_list_lock_release();
    return 0;
}

static inline int
disable_periodic_event(
        struct periodic_event *event)
{
    int res;

    periodic_event_list_lock_acquire();
    DEBUG_ASSERT(num_enabled_periodic_events > 0);
    num_enabled_periodic_events--;

    ilist_remove(&periodic_event_list, &event->list_node);

    if(num_enabled_periodic_events == 0) {
        // Stop the periodic timer
        res = periodic_stop_lockless(); 
        if(res) {
            periodic_event_list_lock_release();
            return res;
        }
    }
    periodic_event_list_lock_release();
    return 0;
}

struct periodic_event *
create_periodic_event(
        duration_t period,
        void *state,
        periodic_callback_f *callback)
{
    struct periodic_event *evt =
        kmalloc(sizeof(struct periodic_event));
    if(evt == NULL) {
        return NULL;
    }
    memset(evt, 0, sizeof(struct periodic_event));

    evt->state = state;
    evt->callback = callback;
    evt->period = period;

    evt->current_period = evt->period;

    int res = enable_periodic_event(evt);
    if(res) {
        kfree(evt);
        return NULL;
    }

    return evt;
}

int
destroy_periodic_event(
        struct periodic_event *event)
{
    int res;

    res = disable_periodic_event(event);
    if(res) {
        return res;
    }

    kfree(event);

    return 0;
}

