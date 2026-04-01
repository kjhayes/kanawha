
#include <kanawha/init.h>
#include <kanawha/kmalloc.h>
#include <kanawha/list.h>
#include <kanawha/lock.h>
#include <kanawha/rwlock.h>
#include <kanawha/scheduler.h>
#include <kanawha/stddef.h>
#include <kanawha/tasklet.h>
#include <kanawha/thread.h>
#include <kanawha/waitqueue.h>

static DECLARE_RLOCK(tasklet_lock);
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

    unsigned owned_name : 1;
    const char *name;

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
    tasklet->owned_name = 0;
    tasklet->name = "unnamed-tasklet";

    irq_lock_init(&tasklet->lock);

    rlock_write_lock(&tasklet_lock);
    ilist_push_tail(&tasklet_list, &tasklet->list_node);
    rlock_write_unlock(&tasklet_lock);

    return tasklet;
}

int
tasklet_name(struct tasklet *task, const char *name)
{
    char *newname = kstrdup(name);
    if(newname == NULL) {
        return -ENOMEM;
    }

    int oldowned = task->owned_name;
    char *oldname = (char*)task->name;
    mbarrier();

    task->name = newname;
    mbarrier(); // without this we could free invalid
                // memory on a race, with this, we can
                // only leak memory (better)
    task->owned_name = 1;

    if(oldowned) {
        kfree((void*)oldname);
    }
    return 0;
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

    rlock_write_lock(&tasklet_lock);
    ilist_remove(&tasklet_list, &tasklet->list_node);
    rlock_write_unlock(&tasklet_lock);

    if(tasklet->owned_name) {
        kfree((void*)tasklet->name);

        // pedantic
        tasklet->owned_name = 0;
        tasklet->name = NULL;
    }
    kfree(tasklet);

    return 0;
}

int
tasklet_trigger(struct tasklet *tasklet)
{
    // No need to grab the lock
    tasklet->pending = 1;
    mbarrier();
    wake_single(&tasklet_waitqueue);
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

    (*tasklet->func)(tasklet->state);
    mbarrier();
    tasklet->pending = 0;
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
        dprintk("handling tasklet \"%s\"\n", tasklet->name);
        (*tasklet->func)(tasklet->state);
        mbarrier();
        tasklet->running = 0;
        return 1;
    } else {
        irq_lock_release(&tasklet->lock);
        return 0;
    }
}

static int
tasklet_handle_all_pending(void)
{
    int num_handled = 0;
    int res;
    rlock_read_lock(&tasklet_lock);
    ilist_node_t *list_node;
    ilist_for_each(list_node, &tasklet_list)
    {
        struct tasklet *tasklet =
            container_of(list_node, struct tasklet, list_node);
        res = tasklet_handle_pending(tasklet);
        if(res < 0) {
            rlock_read_unlock(&tasklet_lock);
            return res;
        }
        num_handled += res;
    }
    rlock_read_unlock(&tasklet_lock);
    return num_handled;
}

static void
tasklet_worker_thread(void *__self)
{
    // Enable IRQ(s) for this thread (ideally forever)
    enable_irqs();

    int res;
    struct tasklet_thread_state *self = __self;
    while(1)
    {
        res = wait_on(&tasklet_waitqueue);
        if(res)
        {
            // This is very weird...
            wprintk("tasklet_worker_thread failed to wait on "
                    "waitqueue?\n");
        }
        dprintk("tasklet worker woke up!\n");

        // Enable every loop incase some tasklet incorrectly disables
        // interrupts
        if(!irqs_enabled()) {
            wprintk("Tasklet incorrectly disabled interrupts! (re-enabling)\n");
            enable_irqs();
        }
        int num_handled = tasklet_handle_all_pending();
        if(num_handled < 0) {
            wprintk("tasklet_handle_all_pending returned error %s\n", errnostr(num_handled));
        }
        if(num_handled == 0) {
            wprintk("tasklet_worker_thread: spurriously awoken (handled no tasklets!)\n");
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

    res = thread_init(&worker->thread_state, tasklet_worker_thread, worker, THREAD_FLAG_TASKLET);
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
