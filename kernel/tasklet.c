
#include <kanawha/tasklet.h>
#include <kanawha/lock.h>
#include <kanawha/list.h>
#include <kanawha/kmalloc.h>
#include <kanawha/stddef.h>
#include <kanawha/thread.h>
#include <kanawha/init.h>
#include <kanawha/scheduler.h>
#include <kanawha/waitqueue.h>

DEFINE_LOCAL_IRQ_LOCK(tasklet_lock);
static DECLARE_ILIST(tasklet_list);

static struct waitqueue tasklet_waitqueue;
static int
init_tasklet_waitqueue(void)
{
    int res;
    res = waitqueue_init(&tasklet_waitqueue);
    if(res) {
	return res;
    }
    waitqueue_name(&tasklet_waitqueue, "tasklet");
    return 0;
}
declare_init(dynamic, init_tasklet_waitqueue);

struct tasklet
{
    tasklet_f *func;
    void *state;

    irq_lock_t lock;

    unsigned killed : 1;
    unsigned pending : 1;
    unsigned running : 1;

    ilist_node_t list_node;
};

struct tasklet *
tasklet_create(
        tasklet_f *func,
        void *state)
{
    struct tasklet *tasklet;
    tasklet = kmalloc(sizeof(*tasklet), KM_KERNEL);

    tasklet->func = func;
    tasklet->state = state;
    tasklet->killed = 0;
    tasklet->pending = 0;
    tasklet->running = 0;

    irq_lock_init(&tasklet->lock);

    tasklet_lock_acquire();
    ilist_push_tail(&tasklet_list, &tasklet->list_node);
    tasklet_lock_release();

    return tasklet;
}

int
tasklet_destroy(
        struct tasklet *tasklet)
{
    irq_lock_acquire(&tasklet->lock);
    if(tasklet->killed) {
        irq_lock_release(&tasklet->lock);
        return -EALREADY;
    } else {
        tasklet->killed = 1;
        mbarrier();
        irq_lock_release(&tasklet->lock);
    }

    while(tasklet->running) {}

    tasklet_lock_acquire();
    ilist_remove(&tasklet_list, &tasklet->list_node);
    tasklet_lock_release();

    kfree(tasklet);

    return 0;
}

int
tasklet_trigger(
        struct tasklet *tasklet)
{
    // No need to grab the lock
    tasklet->pending = 1;
    wake_all(&tasklet_waitqueue);
    return 0;
}

int
tasklet_run(
        struct tasklet *tasklet)
{
    irq_lock_acquire(&tasklet->lock);
    if(tasklet->killed) {
        irq_lock_release(&tasklet->lock);
        return -EINVAL;
    }

    if(tasklet->running) {
        irq_lock_release(&tasklet->lock);
        return -EBUSY;
    }

    tasklet->pending = 0;
    mbarrier();
    (*tasklet->func)(tasklet->state);

    irq_lock_release(&tasklet->lock);

    return 0;
}

static int
tasklet_handle_pending(
        struct tasklet *tasklet)
{
    irq_lock_acquire(&tasklet->lock);
    if(tasklet->killed || tasklet->running) {
        irq_lock_release(&tasklet->lock);
        return 0;
    }

    if(tasklet->pending) {
        tasklet->pending = 0;
        mbarrier();
        (*tasklet->func)(tasklet->state);
    }

    irq_lock_release(&tasklet->lock);

    return 0;
}

static int
tasklet_handle_all_pending(void)
{
    tasklet_lock_acquire();
    ilist_node_t *list_node;
    ilist_for_each(list_node, &tasklet_list) {
        struct tasklet *tasklet =
            container_of(list_node, struct tasklet, list_node);
        tasklet_handle_pending(tasklet);
    }
    tasklet_lock_release();
    return 0;
}

static struct thread_state tasklet_thread_state;
static void
tasklet_thread(void *__in) {
    int res;
    while(1) {
        tasklet_handle_all_pending();
        res = wait_on(&tasklet_waitqueue);
	if(res) {
	    // Weird (but ignore it)
	}
    }
}

static int
init_tasklet_thread(void)
{
    int res;

    res = thread_init(&tasklet_thread_state,
                tasklet_thread,
                NULL,
                0);
    if(res) {
        return res;
    }

    struct scheduler *sched = current_sched();
    if(sched == NULL) {
        thread_deinit(&tasklet_thread_state);
        return -EDEFER;
    }

    res = scheduler_add_thread(sched, &tasklet_thread_state);
    if(res) {
        thread_deinit(&tasklet_thread_state);
        return -EDEFER;
    }

    // Ensure that the thread is awake
    thread_wake(&tasklet_thread_state);

    return 0;
}
declare_init_desc(sched, init_tasklet_thread, "Starting Tasklet Thread");

