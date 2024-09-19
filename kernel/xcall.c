
#include <kanawha/xcall.h>
#include <kanawha/cpu.h>
#include <kanawha/init.h>
#include <kanawha/list.h>
#include <kanawha/percpu.h>
#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/kmalloc.h>
#include <kanawha/assert.h>
#include <kanawha/thread.h>

struct xcall_state
{
    spinlock_t lock;

    ilist_t queue;

    irq_t ipi;
    struct irq_action *action;
};

static DECLARE_PERCPU_VAR(struct xcall_state, xcall_state);

struct pending_xcall
{
    xcall_f *func;
    void *arg;

    ilist_node_t queue_node;
};

static int
xcall_handle_current(void)
{
    int res = 0;

    struct xcall_state *state = percpu_ptr(percpu_addr(xcall_state));
    int irq_flags = spin_lock_irq_save(&state->lock);

    do {
        ilist_node_t *node = ilist_pop_head(&state->queue);
        if(node == NULL) {
            break;
        }

        struct pending_xcall *xcall =
            container_of(node, struct pending_xcall, queue_node);
        
        (*xcall->func)(xcall->arg);

        kfree(xcall);

    } while(1);


    spin_unlock_irq_restore(&state->lock, irq_flags);
    return res;
}

static int
xcall_ipi_handler(
        struct excp_state *excp_state,
        struct irq_action *action)
{
    int res = xcall_handle_current();
    if(res) {
        return res;
    }
    return IRQ_NONE;
}

int
xcall_queue(cpu_id_t cpu, xcall_f *func, void *arg) {
    struct pending_xcall *xcall = kmalloc(sizeof(struct pending_xcall));
    if(xcall == NULL) {
        return -ENOMEM;
    }

    struct xcall_state *state = percpu_ptr_specific(percpu_addr(xcall_state), cpu);

    xcall->func = func;
    xcall->arg = arg;
   
    int res = 0;
    int irq_state = spin_lock_irq_save(&state->lock);

    ilist_push_tail(&state->queue, &xcall->queue_node);

    spin_unlock_irq_restore(&state->lock, irq_state);
    return res;
}

int
xcall_notify(cpu_id_t cpu)
{
    struct thread_state *cur_thread = current_thread();
    DEBUG_ASSERT(cur_thread);
    pin_thread(cur_thread);
    if(cpu == current_cpu_id()) {
        int res = xcall_handle_current();
        unpin_thread(cur_thread);
        return res;
    } else {
        unpin_thread(cur_thread);
        struct xcall_state *state;
        state = percpu_ptr_specific(percpu_addr(xcall_state), cpu);
        return trigger_irq(state->ipi);
    }
}

int
xcall_provide_ipi_irq(cpu_id_t cpu, irq_t irq)
{
    int res;
    struct xcall_state *state = percpu_ptr_specific(percpu_addr(xcall_state), cpu);

    int irq_state = spin_lock_irq_save(&state->lock);
    if(state->ipi != NULL_IRQ && state->action == NULL) {
        struct irq_desc *desc = irq_to_desc(irq);
        if(desc == NULL)
        {
            eprintk("xcall_provide_ipi_irq could not find IRQ 0x%lx for CPU %ld\n",
                    (ul_t)irq, (sl_t)cpu);
            return -ENXIO;
        }

        DEBUG_ASSERT(desc->irq == irq);

        state->action = irq_install_handler(desc, NULL, NULL, xcall_ipi_handler);
        if(state->action == NULL) {
            spin_unlock_irq_restore(&state->lock, irq_state);
            return -EINVAL;
        }
        state->ipi = irq;
    }
    spin_unlock_irq_restore(&state->lock, irq_state);
    return 0;
}

static int
bsp_init_xcalls(void)
{
    for(cpu_id_t cpu = 0; cpu < total_num_cpus(); cpu++) {
        struct xcall_state *state = percpu_ptr_specific(percpu_addr(xcall_state), cpu);
        ilist_init(&state->queue);
        spinlock_init(&state->lock);
        state->ipi = IRQ_NONE;
        state->action = NULL;
    }
    return 0;
}
declare_init_desc(post_topo, bsp_init_xcalls, "Initializing XCall Queues");

