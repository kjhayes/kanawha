
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/scheduler.h>
#include <kanawha/stddef.h>
#include <kanawha/tasklet.h>
#include <kanawha/thread.h>
#include <kanawha/waitqueue.h>

DEFINE_LOCAL_IRQ_LOCK(tasklet_lock);
static DECLARE_ILIST(tasklet_list);

static struct waitqueue tasklet_waitqueue;
static int
init_tasklet_waitqueue(void)
{
    int res;
    res = waitqueue_init(&tasklet_waitqueue);
    if(res)
    {
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
tasklet_create(tasklet_f *func, void *state)
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
tasklet_destroy(struct tasklet *tasklet)
{
    irq_lock_acquire(&tasklet->lock);
    if(tasklet->killed)
    {
        irq_lock_release(&tasklet->lock);
        return -EALREADY;
    }
    else
    {
        tasklet->killed = 1;
        mbarrier();
        irq_lock_release(&tasklet->lock);
    }

    while(tasklet->running)
    {
    }

    tasklet_lock_acquire();
    ilist_remove(&tasklet_list, &tasklet->list_node);
    tasklet_lock_release();

    kfree(tasklet);

    return 0;
}

int
tasklet_trigger(struct tasklet *tasklet)
{
    // No need to grab the lock
    tasklet->pending = 1;
    mbarrier();
    wake_all(&tasklet_waitqueue);
    return 0;
}

int
tasklet_run(struct tasklet *tasklet)
{
    irq_lock_acquire(&tasklet->lock);
    if(tasklet->killed)
    {
        irq_lock_release(&tasklet->lock);
        return -EINVAL;
    }

    if(tasklet->running)
    {
        irq_lock_release(&tasklet->lock);
        return -EBUSY;
    }

    tasklet->running = 1;
    irq_lock_release(&tasklet->lock);

    tasklet->pending = 0;
    mbarrier();
    (*tasklet->func)(tasklet->state);
    mbarrier();
    tasklet->running = 0;

    return 0;
}

static int
tasklet_handle_pending(struct tasklet *tasklet)
{
    irq_lock_acquire(&tasklet->lock);
    if(tasklet->killed || tasklet->running)
    {
        irq_lock_release(&tasklet->lock);
        return 0;
    }

    if(tasklet->pending)
    {
        tasklet->running = 1;
        irq_lock_release(&tasklet->lock);
        tasklet->pending = 0;
        mbarrier();
        (*tasklet->func)(tasklet->state);
        mbarrier();
        tasklet->running = 0;
    } else {
        irq_lock_release(&tasklet->lock);
    }


    return 0;
}

static int
tasklet_handle_all_pending(void)
{
    tasklet_lock_acquire();
    ilist_node_t *list_node;
    ilist_for_each(list_node, &tasklet_list)
    {
        struct tasklet *tasklet =
            container_of(list_node, struct tasklet, list_node);
        tasklet_handle_pending(tasklet);
    }
    tasklet_lock_release();
    return 0;
}

static void
tasklet_worker_thread(void *__self)
{
    int res;
    struct tasklet_thread_state *self = __self;
    while(1)
    {
        // Enable every loop incase some tasklet incorrectly disables
        // interrupts
        enable_irqs();
        tasklet_handle_all_pending();
        res = wait_on(&tasklet_waitqueue);
        if(res)
        {
            // This is very weird...
            wprintk("tasklet_worker_thread failed to wait on "
                    "waitqueue?\n");
        }
    }
}

struct tasklet_worker
{
    struct thread_state thread_state;
};

static struct tasklet_worker *
tasklet_create_worker(void)
{
    int res;

    struct tasklet_worker *worker = kzmalloc(sizeof(*worker), KM_KERNEL);
    if(worker == NULL)
    {
        return NULL;
    }

    res = thread_init(&worker->thread_state, tasklet_worker_thread, worker, 0);
    if(res)
    {
        kfree(worker);
        return NULL;
    }

    struct scheduler *sched = current_sched();
    if(sched == NULL)
    {
        thread_deinit(&worker->thread_state);
        kfree(worker);
        return NULL;
    }

    res = scheduler_add_thread(sched, &worker->thread_state);
    if(res)
    {
        thread_deinit(&worker->thread_state);
        kfree(worker);
        return NULL;
    }

    // Ensure that the thread is awake
    thread_wake(&worker->thread_state);

    return worker;
}

// Having this be a static number of threads sucks,
// This *should* be done dynamically (scaling up and down
// the number of workers with demand)
#define TASKLET_NUM_WORKERS 16
static struct tasklet_worker *workers[TASKLET_NUM_WORKERS];
static int
init_tasklet_thread(void)
{
    int res;
    int num_workers = 0;
    for(int i = 0; i < TASKLET_NUM_WORKERS; i++)
    {
        struct tasklet_worker *wrk = tasklet_create_worker();
        if(wrk == NULL)
        {
            workers[i] = NULL;
        }
        else
        {
            workers[i] = wrk;
            num_workers++;
        }
    }
    if(num_workers <= 0)
    {
        eprintk("Failed to spawn any tasklet workers!\n");
        return -EINVAL;
    }
    else if(num_workers < TASKLET_NUM_WORKERS)
    {
        wprintk("Spawned fewer tasklet worker threads than requested!\n");
    }
    return 0;
}
declare_init_desc(sched, init_tasklet_thread, "Starting Tasklet Thread");
