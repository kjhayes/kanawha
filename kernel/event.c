
#include <kanawha/dev/timer.h>
#include <kanawha/event.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/tasklet.h>
#include <kanawha/types.h>

static size_t num_enabled_periodic_events = 0;
static DECLARE_ILIST(periodic_event_list);
DEFINE_LOCAL_IRQ_LOCK(periodic_event_list_lock);

static duration_t tick_length;

static int periodic_timer_started = 0;

struct periodic_event
{
    duration_t period;
    duration_t current_period;

    ilist_node_t list_node;

    void *state;
    periodic_callback_f *callback;
};

static struct timer_dev *periodic_timer = NULL;

static void
periodic_callback(void)
{
    periodic_event_list_lock_acquire();
    ilist_node_t *node;
    ilist_for_each(node, &periodic_event_list)
    {
        struct periodic_event *event =
            container_of(node, struct periodic_event, list_node);
        if(event->current_period <= tick_length)
        {
            event->current_period = event->period;
            // Run the event callback
            (*event->callback)(event->state);
        }
        else
        {
            event->current_period -= tick_length;
        }
    }
    periodic_event_list_lock_release();
}

static int
periodic_kickstart_lockless(void)
{
    int res;
    if(periodic_timer_started) {
        return 0;
    }

    if(periodic_timer == NULL)
    {
        return -ENODEV;
    }

    tick_length = msec_to_duration(CONFIG_PERIODIC_RESOLUTION_MS);

    res = timer_dev_set_alarm_periodic(periodic_timer,
                                       0,
                                       tick_length,
                                       periodic_callback);
    if(res)
    {
        return res;
    }

    periodic_timer_started = 1;
    return 0;
}

static int
periodic_stop_lockless(void)
{
    return -EUNIMPL;
}

static int
periodic_kickstart(void)
{
    int res = 0;
    periodic_event_list_lock_acquire();
    if(num_enabled_periodic_events > 0) {
        res = periodic_kickstart_lockless();
    }
    periodic_event_list_lock_release();
    return res;
}

static inline int
enable_periodic_event(struct periodic_event *event)
{
    int res;
    periodic_event_list_lock_acquire();
    ilist_push_tail(&periodic_event_list, &event->list_node);
    num_enabled_periodic_events++;

    // kickstart the periodic timer
    res = periodic_kickstart_lockless();
    if(res)
    {
        if(started_init_stage_launch()) {
            ilist_remove(&periodic_event_list, &event->list_node);
            periodic_event_list_lock_release();
            return res;
        }
        // If we are still initializing this might fail because no
        // timer has been registered yet we will try to kickstart
        // periodic events again at launch
    }

    periodic_event_list_lock_release();
    return 0;
}

static inline int
disable_periodic_event(struct periodic_event *event)
{
    int res;

    periodic_event_list_lock_acquire();
    DEBUG_ASSERT(num_enabled_periodic_events > 0);
    num_enabled_periodic_events--;

    ilist_remove(&periodic_event_list, &event->list_node);

    if(num_enabled_periodic_events == 0)
    {
        // Stop the periodic timer
        res = periodic_stop_lockless();
        if(res)
        {
            periodic_event_list_lock_release();
            return res;
        }
    }
    periodic_event_list_lock_release();
    return 0;
}

struct periodic_event *
create_periodic_event(duration_t period,
                      void *state,
                      periodic_callback_f *callback)
{
    int res;

    struct periodic_event *evt =
        kzmalloc(sizeof(struct periodic_event), KM_KERNEL);
    if(evt == NULL)
    {
        return NULL;
    }

    evt->state = state;
    evt->callback = callback;
    evt->period = period;
    evt->current_period = evt->period;

    res = enable_periodic_event(evt);
    if(res)
    {
        kfree(evt);
        return NULL;
    }

    return evt;
}

int
destroy_periodic_event(struct periodic_event *event)
{
    int res;

    res = disable_periodic_event(event);
    if(res)
    {
        return res;
    }

    kfree(event);

    return 0;
}

static int
probe_timer(struct timer_dev *dev)
{
    printk("Periodic Event Subsystem Probing \"%s\"\n",
            timer_dev_get_name(dev));
    if(periodic_timer == NULL)
    {
        return 0;
    }
    return -EALREADY;
}

static int
receive_timer(struct timer_dev *timer)
{
    printk("Periodic Event Subsystem Claiming \"%s\"\n",
            timer_dev_get_name(timer));
    periodic_event_list_lock_acquire();
    if(periodic_timer == NULL)
    {
        periodic_timer = timer;
        periodic_event_list_lock_release();
        return 0;
    }
    periodic_event_list_lock_release();
    return -EALREADY;
}

static int
revoke_timer(struct timer_dev *timer)
{
    periodic_event_list_lock_acquire();
    if(periodic_timer != timer)
    {
        wprintk("tried to revoke timer from periodic event subsystem which was "
                "not owned!"
                " (owned=%s, revoked=%s)\n",
                periodic_timer ? timer_dev_get_name(periodic_timer) : "NULL",
                timer ? timer_dev_get_name(timer) : "NULL");
        periodic_event_list_lock_release();
        return 0; // "success?"
    }
    periodic_stop_lockless();
    periodic_timer = NULL;
    periodic_event_list_lock_release();
    return 0;
}

static struct timer_dev_owner timer_owner = {
    .probe = probe_timer,
    .receive = receive_timer,
    .revoke = revoke_timer,
};
static int
register_periodic_timer_owner(void)
{
    return register_timer_dev_owner(&timer_owner);
}
declare_init(dynamic, register_periodic_timer_owner);

// Extra kickstart in-case 
static int
periodic_event_kickstart_at_launch(void)
{
    return periodic_kickstart();
}
declare_init_desc(launch, periodic_event_kickstart_at_launch, "Kickstart Periodic Event(s)");

