
#include <kanawha/assert.h>
#include <kanawha/atomic.h>
#include <kanawha/attribute.h>
#include <kanawha/errno.h>
#include <kanawha/event.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/kmalloc.h>
#include <kanawha/lock.h>
#include <kanawha/percpu.h>
#include <kanawha/printk.h>
#include <kanawha/proc/process.h>
#include <kanawha/ptree.h>
#include <kanawha/scheduler.h>
#include <kanawha/slab.h>
#include <kanawha/spinlock.h>
#include <kanawha/string.h>
#include <kanawha/thread.h>
#include <kanawha/vmem.h>
#include <kanawha/perf.h>

static void set_current_thread(struct thread_state *state);

static void
dump_thread_flags(struct thread_state *thread,
                  unsigned long flags,
                  printk_f *printer);

static DECLARE_PTREE(thread_tree);
DEFINE_LOCAL_IRQ_LOCK(thread_tree_lock);

DECLARE_LOCAL_PERF_TIMER(thread_init_perf_timer)
DECLARE_LOCAL_PERF_TIMER(arch_init_thread_state_perf_timer)
DECLARE_LOCAL_PERF_TIMER(thread_init_map_global_regions_perf_timer)
DECLARE_LOCAL_PERF_TIMER(thread_init_map_critical_perf_timer)
#define TIMER_START(_TIMER) perf_timer_start(&_TIMER)
#define TIMER_STOP(_TIMER) perf_timer_stop(&_TIMER)

// Global Thread Vmem Mapping Structures
static DECLARE_ILIST(global_vmem_regions);
static struct slab_allocator *global_vmem_region_slab_allocator = NULL;
#define GLOBAL_VMEM_REGIONS_SLAB_BUFFER_SIZE PAGE_SIZE_4KB
static uint8_t
    global_vmem_regions_slab_buffer[GLOBAL_VMEM_REGIONS_SLAB_BUFFER_SIZE];

struct thread_global_vmem_region
{
    void *virtual_addr;
    struct vmem_region *region;
    ilist_node_t list_node;
};

// Should be called with the thread_tree_lock already held
static inline void
get_thread_id(struct thread_state *state)
{
    int res;
    res = ptree_insert_any(&thread_tree, &state->tree_node);
    if(res) {
        state->id = NULL_THREAD_ID;
    }
    state->id = (thread_id_t)state->tree_node.key;
}

DECLARE_PERCPU_VAR(struct thread_state *, __current_thread);
DECLARE_STATIC_PERCPU_VAR(struct thread_state *, __idle_thread);

DEFINE_LOCAL_IRQ_LOCK(thread_status_count_lock);
static size_t thread_status_counts[NUM_THREAD_STATUSES] = { 0 };

size_t
thread_status_count(
        thread_status_t status)
{
    size_t count;
    DEBUG_ASSERT(status < NUM_THREAD_STATUSES);
    thread_status_count_lock_acquire();
    count = thread_status_counts[status];
    thread_status_count_lock_release();
    return count;
}

static inline void
thread_set_status(struct thread_state *thread, thread_status_t status)
{
    if(status == THREAD_STATUS_PREPARING) {
        // We should not previously have had a status
        thread_status_count_lock_acquire();
        thread->status = status;
        thread_status_counts[thread->status]++;
        thread_status_count_lock_release();
        return;
    }

    // We should have the lock held already...
    DEBUG_ASSERT(!(thread->flags & THREAD_FLAG_IDLE)
                 || (status == THREAD_STATUS_READY)
                 || (status == THREAD_STATUS_RUNNING)
                 || (status == THREAD_STATUS_SCHEDULED)
                 );
    DEBUG_ASSERT(thread->status == THREAD_STATUS_PREPARING ||
                 spin_try_lock(&thread->lock) != 0);
    DEBUG_ASSERT(thread->status != THREAD_STATUS_ABANDONED);
#ifdef CONFIG_DEBUG_LOG_THREAD_STATE_CHANGES
    printk("thread(%ld) %s -> %s\n",
           (sl_t)thread->id,
           thread_status_to_string(thread->status),
           thread_status_to_string(status));
#endif

    thread_status_count_lock_acquire();
    DEBUG_ASSERT(thread_status_counts[thread->status] > 0);
    thread_status_counts[thread->status]--;
    thread->status = status;
    thread_status_counts[thread->status]++;
    thread_status_count_lock_release();
}

static int
thread_is_running(struct thread_state *thread)
{
    switch(thread->status) {
        case THREAD_STATUS_RUNNING:
        case THREAD_STATUS_TIRED:
            return 1;
        default:
            break;
    }

    if(thread->running_on != NULL_CPU_ID) {
        return 1;
    }

    return 0;
}

__noreturn void
idle_loop(void)
{
    printk("Entered Idle Thread On CPU %d\n", current_cpu_id());
    enable_irqs();
    while(1)
    {
        if(!irqs_enabled()) {
            panic("Running the idle thread with interrupts disabled!\n");
        }

        size_t num_ready = thread_status_count(THREAD_STATUS_READY);
        if(num_ready > total_num_cpus()) {
            dprintk("Running idle thread when there are %lu threads ready!\n", num_ready);
        }

        arch_halt();

        thread_yield();

        // if(current_cpu_id() == 0 && clk_mono_valid()) {
        //     printk("clk_mono = 0x%lx\n",
        //             clk_mono_current());
        // }
    }
}

struct thread_state *
current_thread(void)
{
    // NOTE: There is a race condition here between obtaining
    //       the pointer and actually dereferencing the pointer
    //       Thus we need to disable preemption by disabling interrupts
    //       TODO: We should add a distinct notion of "preempt_disable"
    int irq_flags;
    irq_flags = disable_save_irqs();
    struct thread_state **ptr = percpu_ptr(percpu_addr(__current_thread));
    // If we were preempted here and then ran on a different
    // CPU, we might claim to be the wrong thread...
    // (This took me faaaaaaar too long to realize)
    struct thread_state *cur = *ptr;
    enable_restore_irqs(irq_flags);
    return cur;
}

static void
set_current_thread(struct thread_state *state)
{
    DEBUG_ASSERT(!irqs_enabled());
    struct thread_state **ptr = percpu_ptr(percpu_addr(__current_thread));
    *ptr = state;
    dprintk("CPU(%ld) setting current thread to id(%ld)\n", (sl_t)current_cpu_id(), (sl_t)state->id);
    mbarrier();
}

int
pin_thread(struct thread_state *thread)
{
    int res;
    int irq_state = spin_lock_irq_save(&thread->lock);
    if(thread->pin_refs > 0)
    {
        thread->pin_refs++;
        if(thread->status == THREAD_STATUS_RUNNING ||
           thread->status == THREAD_STATUS_TIRED)
        {
            thread->pinned_to = thread->running_on;
        }
        res = 0;
    }
    else
    {
        res = -EINVAL;
    }
    spin_unlock_irq_restore(&thread->lock, irq_state);
    return res;
}

int
unpin_thread(struct thread_state *thread)
{
    int res;
    int irq_state = spin_lock_irq_save(&thread->lock);
    if(thread->pin_refs > 0)
    {
        thread->pin_refs--;
        res = 0;
    }
    else
    {
        res = -EINVAL;
    }
    if(thread->pin_refs == 0)
    {
        thread->pinned_to = NULL_CPU_ID;
    }
    spin_unlock_irq_restore(&thread->lock, irq_state);
    return res;
}

int
pin_thread_specific(struct thread_state *state, cpu_id_t cpu)
{
    int res;
    int irq_state = spin_lock_irq_save(&state->lock);
    if(state->pin_refs > 0)
    {
        if(state->pinned_to != cpu)
        {
            res = -EALREADY;
        }
        else
        {
            state->pin_refs++;
            res = 0;
        }
    }
    else
    {
        state->pinned_to = cpu;
        state->pin_refs++;
        res = 0;
    }
    spin_unlock_irq_restore(&state->lock, irq_state);
    return res;
}

struct thread_state *
idle_thread(void)
{
    struct thread_state **ptr = percpu_ptr(percpu_addr(__idle_thread));
    return *ptr;
}

struct thread_state *
cpu_idle_thread(cpu_id_t cpu)
{
    struct thread_state **ptr = percpu_ptr_specific(percpu_addr(__idle_thread), cpu);
    return *ptr;
}

int
thread_init(struct thread_state *state,
            thread_f *func,
            void *in,
            unsigned long flags)
{
    int res;

    TIMER_START(thread_init_perf_timer);

    memset(state, 0, sizeof(*state));

    state->func = func;
    state->in = in;
    state->flags = flags;
    state->pinned_to = NULL_CPU_ID;
    state->pin_refs = 0;
    state->waitqueue = NULL;
    state->scheduled = NULL;
    state->irq_depth = 0;
    thread_set_status(state, THREAD_STATUS_PREPARING);

    time_t now = current_timestamp();
    state->creation_timestamp = now;
    state->last_scheduled_timestamp = now;

    state->mem_map = vmem_map_create();
    if(state->mem_map == NULL)
    {
        TIMER_STOP(thread_init_perf_timer);
        return -ENOMEM;
    }

    spinlock_init(&state->lock);

    TIMER_START(thread_init_map_critical_perf_timer);
    thread_tree_lock_acquire();

    get_thread_id(state);
    if(state->id == NULL_THREAD_ID)
    {
        // We somehow ran out of thread_id_t
        eprintk("thread_init: Ran out of unique thread_id_t!\n");
        thread_tree_lock_release();
        vmem_map_destroy(state->mem_map);
        TIMER_STOP(thread_init_perf_timer);
        return -ENOMEM;
    }

    TIMER_START(thread_init_map_global_regions_perf_timer);
    ilist_node_t *node;
    ilist_for_each(node, &global_vmem_regions)
    {

        struct thread_global_vmem_region *global_region =
            container_of(node, struct thread_global_vmem_region, list_node);

        dprintk(
            "Mapping global vmem region into thread (region virt-base = %p)\n",
            global_region->virtual_addr);
        res = vmem_map_map_region(state->mem_map,
                                  global_region->region,
                                  global_region->virtual_addr);
        if(res)
        {
            eprintk("thread_init: Failed to map in global thread vmem "
                    "region at "
                    "virtual address %p (err=%s)\n",
                    global_region->virtual_addr,
                    errnostr(res));
            TIMER_STOP(thread_init_map_global_regions_perf_timer);
            TIMER_STOP(thread_init_map_critical_perf_timer);
            thread_tree_lock_release();
            vmem_map_destroy(state->mem_map);
            TIMER_STOP(thread_init_perf_timer);
            return res;
        }
        dprintk("Mapped\n");
    }
    TIMER_STOP(thread_init_map_global_regions_perf_timer);

    thread_tree_lock_release();
    TIMER_STOP(thread_init_map_critical_perf_timer);

    TIMER_START(arch_init_thread_state_perf_timer);
    res = arch_init_thread_state(state);
    if(res)
    {
        eprintk("arch_init_thread_state failed (err=%s)!\n", errnostr(res));
        vmem_map_destroy(state->mem_map);
        TIMER_STOP(thread_init_perf_timer);
        return res;
    }
    TIMER_STOP(arch_init_thread_state_perf_timer);

    thread_set_status(state, THREAD_STATUS_READY);

    TIMER_STOP(thread_init_perf_timer);
    return 0;
}

int
thread_deinit(struct thread_state *state)
{
    int res;

    thread_tree_lock_acquire();
    struct ptree_node *rem = ptree_remove(&thread_tree, state->tree_node.key);
    DEBUG_ASSERT(rem == &state->tree_node);
    thread_tree_lock_release();

    res = arch_deinit_thread_state(state);
    if(res)
    {
        return res;
    }
    res = vmem_map_destroy(state->mem_map);
    if(res)
    {
        return res;
    }
    return 0;
}

// READY -> SCHEDULED transition
int
thread_schedule(struct thread_state *state)
{
    dprintk("thread_schedule(state=%p id=%ld)\n", state, state->id);

    struct thread_state *cur_thread = current_thread();
    DEBUG_ASSERT(KERNEL_ADDR(cur_thread));

    if(cur_thread->scheduled != NULL)
    {
        dprintk(
            "thread_schedule: thread already has scheduled a replacement!\n");
        return -EALREADY;
    }

    int irq_flags = disable_save_irqs();

    if(state->flags & THREAD_FLAG_IDLE)
    {
        DEBUG_ASSERT(state->pinned_to == current_cpu_id());
        // If it's the idle thread, then we should have exclusive access
        enable_restore_irqs(irq_flags);
        irq_flags = spin_lock_irq_save(&state->lock);
    }
    else
    {
        if(spin_try_lock(&state->lock))
        {
            enable_restore_irqs(irq_flags);
            return -EBUSY;
        }
    }

    if(state->status != THREAD_STATUS_READY)
    {
        if(state->flags & THREAD_FLAG_IDLE) {
            panic("Failed to schedule the idle thread on CPU %ld! (status=%s)\n",
                    current_cpu_id(),
                    thread_status_to_string(state->status));
        }
        spin_unlock_irq_restore(&state->lock, irq_flags);
        return -EINVAL;
    }

    if(state->pin_refs && state->pinned_to != current_cpu_id())
    {
        spin_unlock_irq_restore(&state->lock, irq_flags);
        eprintk("Tried to schedule thread %lld on CPU(%ld) but thread is "
                "pinned to CPU (%ld)\n",
                state->id,
                (sl_t)current_cpu_id(),
                (sl_t)state->pinned_to);
        return -EINVAL;
    }

    thread_set_status(state, THREAD_STATUS_SCHEDULED);
    cur_thread->scheduled = state;
    cur_thread->scheduled->last_scheduled_timestamp = current_timestamp();

    // printk("Scheduling thread(%ld) to take over from thread(%ld)\n",
    //         (sl_t)state->id,
    //         (sl_t)cur_thread->id);

    spin_unlock_irq_restore(&state->lock, irq_flags);
    return 0;
}

static __noreturn void
__thread_switch_threadless(void *in)
{
    // We should be running with IRQ(s) disabled, and thus pinned to the
    // current CPU
    struct thread_state *switching_from = current_thread();
    struct thread_state *switching_to = (struct thread_state *)in;

    DEBUG_ASSERT_MSG(!irqs_enabled(), "IRQ(s) cannot be enabled during __thread_switch_threadless!");

    DEBUG_ASSERT(KERNEL_ADDR(switching_to));

    // TIRED -> SLEEPING or RUNNING -> READY transition
    switch(switching_from->status)
    {
    case THREAD_STATUS_TIRED:
        thread_set_status(switching_from, THREAD_STATUS_SLEEPING);
        break;
    case THREAD_STATUS_RUNNING:
        thread_set_status(switching_from, THREAD_STATUS_READY);
        break;
    default:
        // This should be caught earlier
        panic("__thread_switch_threadless: switching from non-RUNNING or "
              "TIRED "
              "thread!\n");
        break;
    }

    // SCHEDULED -> RUNNING transition
    DEBUG_ASSERT(switching_to->status == THREAD_STATUS_SCHEDULED);
    thread_set_status(switching_to, THREAD_STATUS_RUNNING);

    switching_from->running_on = NULL_CPU_ID;
    switching_to->running_on = current_cpu_id();

    set_current_thread(switching_to);

    DEBUG_ASSERT(current_thread() == switching_to);
    mbarrier();

    dprintk("activating vmem_map of new thread!\n");
    DEBUG_ASSERT(KERNEL_ADDR(switching_to->mem_map));
    vmem_map_activate(switching_to->mem_map);

    spin_unlock(&switching_from->lock);
    spin_unlock(&switching_to->lock);

    dprintk("running new thread\n");

    arch_thread_run_thread(switching_to);

    panic("Returned from arch_thread_run_thread!\n");
}

int
thread_yield(void)
{
    int res;

    struct thread_state *cur_thread;
    cur_thread = current_thread();
    DEBUG_ASSERT(cur_thread);

    struct thread_state *scheduled = cur_thread->scheduled;
    if(scheduled == NULL)
    {
        return 0;
    }

    int irq_flags =
        spin_lock_pair_irq_save(&cur_thread->lock, &scheduled->lock);
    dprintk("thread_yield %p -> %p\n", cur_thread, scheduled);

    DEBUG_ASSERT(scheduled->status == THREAD_STATUS_SCHEDULED);
    DEBUG_ASSERT(scheduled->pin_refs == 0 ||
                 scheduled->pinned_to == current_cpu_id());

    // This will unlock the locks
    // if(cur_thread != NULL)
    // {
    cur_thread->scheduled = NULL;
    arch_thread_run_threadless(__thread_switch_threadless, scheduled);
    // }
    // else
    // {
    //     __thread_switch_threadless(scheduled);
    // }

    enable_restore_irqs(irq_flags);

    dprintk("Returned from thread yield (thread=%p)\n", current_thread());

    return 0;
}

int
thread_switch(void)
{
    int res;

    int irq_flags = disable_save_irqs();

    struct thread_state *cur_thread;
    cur_thread = current_thread();
    DEBUG_ASSERT(cur_thread);

    struct thread_state *scheduled = cur_thread->scheduled;
    if(scheduled == NULL)
    {
        panic("Called thread_switch without a scheduled thread!\n");
        enable_restore_irqs(irq_flags);
        return -EINVAL;
    }

    DEBUG_ASSERT(current_thread_is_rescheduled());

    spin_lock_pair(&cur_thread->lock, &scheduled->lock);
    dprintk("thread_switch %p -> %p\n", cur_thread, scheduled);

    DEBUG_ASSERT(scheduled->status == THREAD_STATUS_SCHEDULED);
    DEBUG_ASSERT(scheduled->pin_refs == 0 ||
                 scheduled->pinned_to == current_cpu_id());

    // This will unlock the locks
    cur_thread->scheduled = NULL;
    arch_thread_run_threadless(__thread_switch_threadless, scheduled);

    enable_restore_irqs(irq_flags);

    dprintk("Returned from thread switch (thread=%p)\n", current_thread());

    return 0;
}

int
thread_tire(struct thread_state *thread)
{
    int irq_flags = spin_lock_irq_save(&thread->lock);

    switch(thread->status)
    {
    case THREAD_STATUS_RUNNING:
        thread_set_status(thread, THREAD_STATUS_TIRED);
        break;
    case THREAD_STATUS_READY:
        thread_set_status(thread, THREAD_STATUS_SLEEPING);
        break;
    case THREAD_STATUS_SLEEPING:
    case THREAD_STATUS_TIRED:
        // We're already in the right state
        break;
    default:
        spin_unlock_irq_restore(&thread->lock, irq_flags);
        return -EINVAL;
    }

    spin_unlock_irq_restore(&thread->lock, irq_flags);

    return 0;
}

int
thread_wake(struct thread_state *thread)
{
    int irq_flags = spin_lock_irq_save(&thread->lock);

    switch(thread->status)
    {
    case THREAD_STATUS_TIRED:
        thread_set_status(thread, THREAD_STATUS_RUNNING);
        break;
    case THREAD_STATUS_SLEEPING:
        thread_set_status(thread, THREAD_STATUS_READY);
        break;
    case THREAD_STATUS_READY:
    case THREAD_STATUS_RUNNING:
        // We're already in the right state
        break;
    default:
        spin_unlock_irq_restore(&thread->lock, irq_flags);
        return -EINVAL;
    }

    spin_unlock_irq_restore(&thread->lock, irq_flags);

    return 0;
}

__noreturn void
thread_abandon(void)
{
    int res;

    // We won't return, so we don't need to save the irq state
    disable_irqs();

    struct thread_state *cur_thread = current_thread();

    if(cur_thread->scheduled == NULL)
    {
        res = thread_schedule(idle_thread());
        if(res)
        {
            panic("Failed to schedule idle thread during "
                  "thread_abandon(NULL)! "
                  "(err=%s)\n",
                  errnostr(res));
        }
    }

    struct thread_state *scheduled = cur_thread->scheduled;

    DEBUG_ASSERT(KERNEL_ADDR(scheduled));
    DEBUG_ASSERT(scheduled->status == THREAD_STATUS_SCHEDULED);

    DEBUG_ASSERT(KERNEL_ADDR(cur_thread));
    DEBUG_ASSERT(cur_thread->waitqueue == NULL);
    DEBUG_ASSERT(KERNEL_ADDR(cur_thread->mem_map));
    DEBUG_ASSERT(cur_thread->tree_node.key == cur_thread->id);

    spin_lock(&cur_thread->lock);
    if(cur_thread->flags & THREAD_FLAG_IDLE)
    {
        panic("Tried to abandon CPU (%ld) idle thread!\n",
              (sl_t)current_cpu_id());
    }
    switch(cur_thread->status)
    {
    case THREAD_STATUS_RUNNING:
    case THREAD_STATUS_TIRED:
        thread_set_status(cur_thread, THREAD_STATUS_ABANDONED);
        cur_thread->running_on = NULL_CPU_ID;
        break;
    default:
        panic("thread_abandon: switching from suspended thread!\n");
    }
    spin_unlock(&cur_thread->lock);

    spin_lock(&scheduled->lock);
    switch(scheduled->status)
    {
    case THREAD_STATUS_SCHEDULED:
        thread_set_status(scheduled, THREAD_STATUS_RUNNING);
        scheduled->running_on = current_cpu_id();
        break;
    default:
        spin_unlock(&scheduled->lock);
        panic("CPU (%ld) new thread %p was not SCHEDULED during "
              "thread_abandon!\n",
              (sl_t)current_cpu_id(),
              scheduled);
    }
    spin_unlock(&scheduled->lock);

    set_current_thread(scheduled);
    DEBUG_ASSERT(current_thread() == scheduled);

    dprintk("Abandoning thread %p for thread %p\n", cur_thread, scheduled);

    res = vmem_map_activate(scheduled->mem_map);
    if(res)
    {
        panic("Failed to activate new thread vmem_map during "
              "thread_abandon! "
              "(err=%s)\n",
              errnostr(res));
    }

    arch_thread_run_thread(scheduled);
}

__noreturn void
cpu_start_threading(thread_f *func, void *state)
{
    int res;

    // We won't return this this "thread" because it doesn't really exist, so
    // we can just leave IRQ(s) disabled
    disable_irqs();

    dprintk("cpu_start_threading (CPU %ld)\n", (sl_t)current_cpu_id());

    if(current_thread() != NULL)
    {
        while(1)
        {
            panic("Called cpu_start_threading() while "
                  "current_thread() != "
                  "NULL!\n");
        }
    }
    if(idle_thread() != NULL)
    {
        while(1)
        {
            panic("Called cpu_start_threading() while idle_thread() "
                  "!= NULL!\n");
        }
    }

    // Create the initial thread for this CPU
    struct thread_state *current =
        kmalloc(sizeof(struct thread_state), KM_KERNEL);
    if(current == NULL)
    {
        panic("Ran out of memory during cpu_start_threading!\n");
    }

    res = thread_init(current, func, state, THREAD_FLAG_IDLE);
    if(res)
    {
        panic("Failed to create initial thread on CPU (%ld) (err=%s)\n",
              (long)current_cpu_id(),
              errnostr(res));
    }

    printk("Created initial thread on CPU (%ld)\n", (long)current_cpu_id());

    pin_thread_specific(current, current_cpu_id());

    // Our first thread on each core, must never return,
    // it must become our idle thread.
    struct thread_state **idle = percpu_ptr(percpu_addr(__idle_thread));
    *idle = current;

    spin_lock(&current->lock);
    thread_set_status(current, THREAD_STATUS_RUNNING);
    current->running_on = current_cpu_id();
    set_current_thread(current);
    DEBUG_ASSERT(current_thread() == current);
    spin_unlock(&current->lock);

    dprintk("cpu_start_threading: Activating Thread Virtual Memory Mapping\n");
    vmem_map_activate(current->mem_map);

    dprintk("cpu_start_threading: Running Initial Thread\n");
    arch_thread_run_thread(current);
}

static void
dump_thread_flags(struct thread_state *thread,
                  unsigned long flags,
                  printk_f *printer)
{
    if(flags == 0)
    {
        return;
    }
    (*printer)(" ");
    if(flags & THREAD_FLAG_IDLE)
    {
        (*printer)("[IDLE]");
    }
    if(flags & THREAD_FLAG_TASKLET)
    {
        (*printer)("[TASKLET]");
    }
    if(flags & THREAD_FLAG_PROCESS)
    {
        struct process *process = container_of(thread, struct process, thread);
        (*printer)("[PROCESS(%ld)]", (sl_t)process->id);
#ifdef CONFIG_DEBUG_TRACK_PROCESS_EXEC
        (*printer)("[EXEC(%s)]",
                   process->tracked_exec != NULL ? process->tracked_exec
                                                 : "UNKNOWN");
#endif
    }
}

int
dump_threads(printk_f *printer)
{
    thread_tree_lock_acquire();

    (*printer)("--- Threads ---\n");
    struct ptree_node *node = ptree_get_first(&thread_tree);
    for(; node != NULL; node = ptree_get_next(node))
    {
        struct thread_state *thread =
            container_of(node, struct thread_state, tree_node);
        (*printer)("\tThread(%ld): %s",
                   (sl_t)thread->id,
                   thread_status_to_string(thread->status));

        dump_thread_flags(thread, thread->flags, printer);

        if(thread->status == THREAD_STATUS_RUNNING)
        {
            (*printer)(" CPU(%ld)", (sl_t)thread->running_on);
        }
        if(thread->pin_refs)
        {
            (*printer)(" PINNED(%ld) PIN-REFS(%ld)",
                       (sl_t)thread->pinned_to,
                       (sl_t)thread->pin_refs);
        }
        if(thread->waitqueue != NULL)
        {
            // There is a race condition here, but this dump is for
            // debugging (usually during a panic) so we just want to
            // get as much information as possible.
            DEBUG_ASSERT(KERNEL_ADDR(thread->waitqueue));
            DEBUG_ASSERT(KERNEL_ADDR(thread->waitqueue->name));
            (*printer)(" WAITING-ON(%s)", thread->waitqueue->name);
        }

        (*printer)("\n");
    }
    (*printer)("---------------\n");

    thread_tree_lock_release();
    return 0;
}

#ifdef CONFIG_DEBUG_DUMP_THREADS_PERIODICALLY
static struct periodic_event *debug_dump_threads_event = NULL;
static void
debug_dump_threads_periodically(void *state)
{
    dump_threads(do_printk);
}
static int
init_debug_dump_threads_periodically(void)
{
    debug_dump_threads_event = create_periodic_event(
        sec_to_duration(CONFIG_DEBUG_DUMP_THREADS_PERIODICALLY_PERIOD),
        NULL,
        debug_dump_threads_periodically);
    if(debug_dump_threads_event == NULL)
    {
        return -EINVAL;
    }
    return 0;
}
declare_init(launch, init_debug_dump_threads_periodically);
#endif

static int
global_vmem_region_slab_alloc_static_init(void)
{
    if(global_vmem_region_slab_allocator != NULL)
    {
        return -EINVAL;
    }

    global_vmem_region_slab_allocator =
        create_static_slab_allocator(global_vmem_regions_slab_buffer,
                                     GLOBAL_VMEM_REGIONS_SLAB_BUFFER_SIZE,
                                     sizeof(struct thread_global_vmem_region),
                                     orderof(struct thread_global_vmem_region));
    if(global_vmem_region_slab_allocator == NULL)
    {
        return -ENOMEM;
    }

    return 0;
}
declare_init(static, global_vmem_region_slab_alloc_static_init);

static struct thread_global_vmem_region *
alloc_thread_global_vmem_region(void)
{
    struct thread_global_vmem_region *region =
        slab_alloc(global_vmem_region_slab_allocator);
    dprintk("alloc_thread_global_vmem_region() -> %p (list_node=%p)\n",
            &region,
            &region->list_node);
    return region;
}

// static void
// free_thread_global_vmem_region(struct thread_global_vmem_region *region) {
//     dprintk("free_thread_global_vmem_region() -> %p (list_node=%p)\n",
//     &region, &region->list_node);
//     slab_free(global_vmem_region_slab_allocator, region);
// }

static void
thread_force_mapping_visitor(struct ptree_node *node, void *state)
{
    struct thread_state *thread =
        container_of(node, struct thread_state, tree_node);
    struct thread_global_vmem_region *global_region = state;

    int res = vmem_map_map_region(thread->mem_map,
                                  global_region->region,
                                  global_region->virtual_addr);
    if(res)
    {
        eprintk("thread_force_mapping_visitor: Failed to map region into "
                "thread %p (err=%s)\n",
                thread,
                errnostr(res));
    }
}

int
thread_force_mapping(struct vmem_region *region, void *virtual_addr)
{
    int res;

    dprintk("Thread Force Mapping [%p-%p) -> %p\n",
            virtual_addr,
            virtual_addr + region->size,
            region);

    thread_tree_lock_acquire();

    struct thread_global_vmem_region *global_region =
        alloc_thread_global_vmem_region();
    if(region == NULL)
    {
        thread_tree_lock_release();
        return -ENOMEM;
    }
    memset(global_region, 0, sizeof(struct thread_global_vmem_region));

    global_region->region = region;
    global_region->virtual_addr = virtual_addr;

    ptree_for_each(&thread_tree, thread_force_mapping_visitor, global_region);

    ilist_push_tail(&global_vmem_regions, &global_region->list_node);

    thread_tree_lock_release();

    return 0;
}

int
thread_relax_mapping(void *virtual_addr)
{
    return -EUNIMPL;
}

const char *
thread_status_to_string(thread_status_t status)
{
    return status == THREAD_STATUS_RUNNING     ? "RUNNING"
           : status == THREAD_STATUS_SCHEDULED ? "SCHEDULED"
           : status == THREAD_STATUS_READY     ? "READY"
           : status == THREAD_STATUS_TIRED     ? "TIRED"
           : status == THREAD_STATUS_SLEEPING  ? "SLEEPING"
           : status == THREAD_STATUS_PREPARING ? "PREPARING"
           : status == THREAD_STATUS_ABANDONED ? "ABANDONED"
                                               : "ERROR-INVALID-STATUS";
}

#define SAMPLE_THREAD_RUNNING_PERIOD_MS (5000 / 64)

static int
tick_thread_running_percent(
        struct thread_state *state)
{
    state->running_tracker = (state->running_tracker << 1ULL);
    int running = thread_is_running(state);
    state->running_tracker |= (typeof(state->running_tracker))running;
    return running;
}

static struct periodic_event *sample_thread_running_event = NULL;
static void
sample_thread_running_percentage(void *state)
{
    __maybe_unused int total_running = 0;

    thread_tree_lock_acquire();
    struct ptree_node *pnode = ptree_get_first(&thread_tree);
    while(pnode) {
        struct thread_state *thread = container_of(
                pnode,
                struct thread_state,
                tree_node);

        total_running += tick_thread_running_percent(thread); 

        pnode = ptree_get_next(pnode);
    }
    thread_tree_lock_release();
//    if(total_running < total_num_cpus()) {
//        printk("Weird: total running = %ld, num cpus = %ld?\n",
//                (sl_t)total_running,
//                (sl_t)total_num_cpus());
//        dump_threads(do_printk);
//    }
}
static int
init_sample_thread_running_percentage(void)
{
    sample_thread_running_event = create_periodic_event(
        msec_to_duration(SAMPLE_THREAD_RUNNING_PERIOD_MS),
        NULL,
        sample_thread_running_percentage);
    if(sample_thread_running_event == NULL)
    {
        return -EINVAL;
    }
    return 0;
}
declare_init(launch, init_sample_thread_running_percentage);

ssize_t
thread_running_percentage(
        struct thread_state *thread)
{
    if(thread->running_tracker == 0) {
        return 0;
    } else {
        size_t num = __builtin_popcountl(thread->running_tracker);
        size_t den = sizeof(thread->running_tracker) * 8;
        ssize_t percent = ((num * 100)/den);
        dprintk("tracker=0x%lx, num=%ld, den=%ld, percent=%ld\n",
                (ul_t)thread->running_tracker,
                (sl_t)num,
                (sl_t)den,
                (sl_t)percent);
        return percent;
    }
}

ssize_t
all_threads_running_percentage(void) {
    ssize_t total = 0;
    thread_tree_lock_acquire();
    struct ptree_node *pnode = ptree_get_first(&thread_tree);
    while(pnode) {
        struct thread_state *thread = container_of(
                pnode,
                struct thread_state,
                tree_node);

        total += thread_running_percentage(thread);

        pnode = ptree_get_next(pnode);
    }
    thread_tree_lock_release();
    return total;
}

