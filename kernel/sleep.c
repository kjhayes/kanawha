
#include <kanawha/sleep.h>
#include <kanawha/waitqueue.h>
#include <kanawha/timer.h>
#include <kanawha/clk.h>

//static void
//thread_sleep_callback(void *state)
//{
//    struct waitqueue *queue = state;
//    DEBUG_ASSERT(KERNEL_ADDR(state));
//
//    printk("Sleep One-Shot Callback: Waking Thread\n");
//    waitqueue_disable(queue);
//    wake_all(queue);
//}

int
thread_sleep(
        duration_t duration,
        unsigned long flags)
{
    int res;

    // Make our own waitqueue and wait on it untill a timer
    // wakes us up.

    // Do it the dumb way
    clk_delay(duration);

//    struct waitqueue queue;
//    res = waitqueue_init(&queue);
//    if(res) {
//        return res;
//    }
//
//    printk("Setting Sleep One-Shot Timer\n");
//    res = timer_set_oneshot(
//        duration,
//        thread_sleep_callback,
//        &queue);
//    if(res) {
//        return res;
//    }
//
//    printk("Sleep Waiting on Queue\n");
//    res = wait_on(&queue);
//    if(res) {
//        return res;
//    }

    return 0;
}

