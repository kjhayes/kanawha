
#include <kanawha/clk.h>
#include <kanawha/event.h>
#include <kanawha/mbarrier.h>
#include <kanawha/sleep.h>
#include <kanawha/waitqueue.h>

static void
thread_sleep_callback(void *state)
{
    int res;

    struct waitqueue *queue = state;
    DEBUG_ASSERT(KERNEL_ADDR(state));

    dprintk("thread_sleep_callback: Waking Thread state=%p\n", state);

    res = waitqueue_disable(queue);
    if(res)
    {
        panic("Failed to disable waitqueue in sleep callback!\n");
    }
    res = wake_all(queue);
    if(res)
    {
        panic("Failed to wake all threads sleeping on waitqueue!\n");
    }
}

int
thread_sleep(duration_t duration, unsigned long flags)
{
    int res;

    struct waitqueue queue;
    res = waitqueue_init(&queue);
    if(res)
    {
        return res;
    }

    waitqueue_name(&queue, "sleep");

    struct periodic_event *evt =
        create_periodic_event(duration, &queue, thread_sleep_callback);

    dprintk("thread_sleep: waiting on queue...\n");
    res = wait_on(&queue);
    if(res)
    {
        destroy_periodic_event(evt);
        mbarrier();
        waitqueue_deinit(&queue);
        return res;
    }

    dprintk("thread_sleep: woke up!\n");

    destroy_periodic_event(evt);
    mbarrier();
    waitqueue_deinit(&queue);

    return 0;
}
