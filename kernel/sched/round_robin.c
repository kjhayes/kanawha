
#include <kanawha/scheduler.h>
#include <kanawha/stddef.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/percpu.h>
#include <kanawha/init.h>
#include <kanawha/time.h>
#include <kanawha/timer.h>
#include <kanawha/xcall.h>
#include <kanawha/vmem.h>
#include <kanawha/assert.h>

struct rr_thread {
    struct thread_state *state;

    ilist_node_t list_node;
};

struct rr_scheduler {
    struct scheduler sched;

    spinlock_t list_lock;
    size_t num_threads;
    ilist_t thread_list;

    struct rr_thread * __percpu *current_rr_thread;
};

static void
rr_sched_kick_xcall(void *in) {
    dprintk("rr_sched_kick_xcall\n");
}

static void
rr_sched_kick(void *in)
{
    int res;

    struct rr_scheduler *sched = in;
    dprintk("rr_sched_kick\n");

    res = xcall_broadcast(rr_sched_kick_xcall, NULL);
    if(res) {
        eprintk("rr_sched_kick broadcast failed (err=%s)\n",
                errnostr(res));
    }
}

static struct scheduler *
rr_sched_alloc_instance(
        struct scheduler_type *type)
{
    struct rr_scheduler *sched = kmalloc(sizeof(struct rr_scheduler));
    if(sched == NULL) {
        return NULL;
    }
    memset(sched, 0, sizeof(struct rr_scheduler));

    sched->current_rr_thread = percpu_calloc(sizeof(struct rr_thread*));
    if(sched->current_rr_thread == PERCPU_NULL) {
        kfree(sched);
        return NULL;
    }

    sched->num_threads = 0;
    ilist_init(&sched->thread_list);
    spinlock_init(&sched->list_lock);

    struct timer_event *event = timer_set_periodic(msec_to_duration(20), rr_sched_kick, sched);
    if(event == NULL) {
        eprintk("Failed to set rr_sched periodic kick!\n");
    }

    return &sched->sched;
}

static int
rr_sched_free_instance(
        struct scheduler_type *type,
        struct scheduler *sched)
{
    struct rr_scheduler *rr_sched =
        container_of(sched, struct rr_scheduler, sched);

    percpu_free(rr_sched->current_rr_thread, sizeof(struct rr_thread*));
    kfree(rr_sched);

    return 0;
}

static struct thread_state *
rr_sched_force_resched(struct scheduler *sched)
{
    struct rr_scheduler *rr_sched =
        container_of(sched, struct rr_scheduler, sched);
   
    int irq_flags = spin_lock_irq_save(&rr_sched->list_lock);

    if(rr_sched->num_threads == 0) {
        spin_unlock_irq_restore(&rr_sched->list_lock, irq_flags);
        dprintk("rr_sched_force_resched without any threads!\n");
        return NULL;
    }


    struct rr_thread **current_ptr = (struct rr_thread**)percpu_ptr(rr_sched->current_rr_thread);
    struct rr_thread *current = *current_ptr;
    struct rr_thread *running  = current;
    struct rr_thread *next = NULL;

    do {
        if(current == NULL || current->list_node.next == &rr_sched->thread_list) {
            next = container_of(rr_sched->thread_list.next, struct rr_thread, list_node);
        } else {
            next = container_of(current->list_node.next, struct rr_thread, list_node);
        }

        if(next == running) {
            spin_unlock_irq_restore(&rr_sched->list_lock, irq_flags);
            return NULL;
        }

        if(running == NULL) {
            running = next;
        }

        current = next;

        DEBUG_ASSERT(KERNEL_ADDR(current));
        DEBUG_ASSERT(KERNEL_ADDR(current->state));

        int res = thread_schedule(current->state);
        if(res) {
            continue;
        } else {
            break;
        }

    } while(1);

    *current_ptr = current;
    spin_unlock_irq_restore(&rr_sched->list_lock, irq_flags);

    dprintk("scheduling thread (%lld)\n", (ull_t)current->state->id);
    return current->state;
}

static struct thread_state *
rr_sched_query_resched(struct scheduler *sched)
{
    dprintk("rr_sched_query_resched CPU (%ld)\n", (sl_t)current_cpu_id());
    return rr_sched_force_resched(sched);
}

static int
rr_sched_add_thread(
        struct scheduler *sched,
        struct thread_state *state)
{
    dprintk("rr_sched_add_thread(%ld)\n",
            state->id);
    struct rr_scheduler *rr_sched =
        container_of(sched, struct rr_scheduler, sched);

    struct rr_thread *thread = kmalloc(sizeof(struct rr_thread));
    if(thread == NULL) {
        return -ENOMEM;
    }
    memset(thread, 0, sizeof(struct rr_thread));

    thread->state = state;
    int irq_flags = spin_lock_irq_save(&rr_sched->list_lock);
    ilist_push_tail(&rr_sched->thread_list, &thread->list_node);
    rr_sched->num_threads++;
    spin_unlock_irq_restore(&rr_sched->list_lock, irq_flags);

    return 0;
}

static int
rr_sched_remove_thread(
        struct scheduler *sched,
        struct thread_state *state)
{
    dprintk("rr_sched_remove_thread(%ld)\n",
            state->id);

    struct rr_scheduler *rr_sched =
        container_of(sched, struct rr_scheduler, sched);


    int irq_flags = spin_lock_irq_save(&rr_sched->list_lock);

    ilist_node_t *node;
    ilist_for_each(node, &rr_sched->thread_list) {
        struct rr_thread *thread =
            container_of(node, struct rr_thread, list_node);
        if(thread->state == state) {
            ilist_remove(&rr_sched->thread_list, &thread->list_node);
            rr_sched->num_threads--;
            struct rr_thread **current_ptr = (struct rr_thread**)percpu_ptr(rr_sched->current_rr_thread);
            if((*current_ptr)->state == state) {
                *current_ptr = NULL;
            }
            spin_unlock_irq_restore(&rr_sched->list_lock, irq_flags);
            return 0;
        }
    }
    spin_unlock_irq_restore(&rr_sched->list_lock, irq_flags);

    return -ENXIO;
}

static struct scheduler_type
rr_sched_type = {
    .name = "rr_sched",
    .type_ops.alloc_instance = rr_sched_alloc_instance,
    .type_ops.free_instance = rr_sched_free_instance,

    .instance_ops.query_resched = rr_sched_query_resched,
    .instance_ops.force_resched = rr_sched_force_resched,
    .instance_ops.remove_thread = rr_sched_remove_thread,
    .instance_ops.add_thread = rr_sched_add_thread,
};

static int
rr_sched_register(void) {
    return register_scheduler_type(&rr_sched_type);
}
declare_init(dynamic, rr_sched_register);

