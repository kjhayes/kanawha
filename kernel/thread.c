
#include <kanawha/thread.h>
#include <kanawha/printk.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/irq.h>
#include <kanawha/percpu.h>
#include <kanawha/init.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/atomic.h>
#include <kanawha/scheduler.h>
#include <kanawha/vmem.h>
#include <kanawha/slab.h>
#include <kanawha/process.h>
#include <kanawha/assert.h>

static DECLARE_SPINLOCK(thread_tree_lock);
static DECLARE_PTREE(thread_tree);

static thread_id_t __next_thread_id = 0;

// Global Thread Vmem Mapping Structures
static DECLARE_ILIST(global_vmem_regions);
static struct slab_allocator *global_vmem_region_slab_allocator = NULL;
#define GLOBAL_VMEM_REGIONS_SLAB_BUFFER_SIZE PAGE_SIZE_4KB
static uint8_t global_vmem_regions_slab_buffer[GLOBAL_VMEM_REGIONS_SLAB_BUFFER_SIZE];

struct thread_global_vmem_region
{
    vaddr_t virtual_addr;
    struct vmem_region *region;
    ilist_node_t list_node;
};

// Should be called with the thread_tree_lock already held
static inline void
get_thread_id(struct thread_state *state)
{
    thread_id_t id;

    signed long num_loops = 0;

    /*
     * This is overly complicated to deal with overflow
     * but overflow will almost certainly never happen
     * with a 64-bit thread_id_t
     */
    while(1) {
        id = __next_thread_id;
        __next_thread_id++;
        // Signed Overflow
        if(__next_thread_id < 0) {
            __next_thread_id = 0;
        }
        dprintk("get_thread_id: checking %ld\n", id);
        struct ptree_node *node = ptree_get(&thread_tree, id);
        if(node == NULL) {
            dprintk("get_thread_id: using %ld\n", id);
            state->id = id;
            ptree_insert(&thread_tree, &state->tree_node, state->id);
            return;
        }
        dprintk("get_thread_id: %ld already taken\n", id);
        num_loops++;
        if(num_loops < 0) {
            // Overflow,
            // we've been searching for way too long,
            // if it's come to this we've somehow exhausted
            // every single thread_id_t???
            state->id = NULL_THREAD_ID;
            return;
        }
    }
}

DECLARE_STATIC_PERCPU_VAR(struct thread_state *, __current_thread);
DECLARE_STATIC_PERCPU_VAR(struct thread_state *, __idle_thread);

__attribute__((noreturn))
void
idle_loop(void) {
    printk("Entered Idle Thread On CPU %d\n", current_cpu_id());
    enable_irqs();
    while(1) {
    }
}

struct thread_state *
current_thread(void)
{
    struct thread_state **ptr = 
        percpu_ptr(percpu_addr(__current_thread));

    return *ptr;
}

int
pin_thread(struct thread_state *thread)
{
    int res;
    int irq_state = spin_lock_irq_save(&thread->lock);
    if(thread->pin_refs > 0) {
        thread->pin_refs++;
        if(thread->status == THREAD_STATUS_RUNNING || thread->status == THREAD_STATUS_TIRED) {
            thread->pinned_to = thread->running_on;
        }
        res = 0;
    } else {
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
    if(thread->pin_refs > 0) {
        thread->pin_refs--;
        res = 0;
    } else {
        res = -EINVAL;
    }
    if(thread->pin_refs == 0) {
        thread->pinned_to = NULL_CPU_ID;
    }
    spin_unlock_irq_restore(&thread->lock, irq_state);
    return res;
}

int
pin_thread_specific(
        struct thread_state *state,
        cpu_id_t cpu)
{
    int res;
    int irq_state = spin_lock_irq_save(&state->lock);
    if(state->pin_refs > 0) {
        if(state->pinned_to != cpu) {
            res = -EALREADY;
        } else {
            state->pin_refs++;
            res = 0;
        }
    } else {
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
    struct thread_state **ptr = 
        percpu_ptr(percpu_addr(__idle_thread));
    return *ptr;
}

int
thread_init(
        struct thread_state *state,
        thread_f *func,
        void *in,
        unsigned long flags)
{
    int res;

    memset(state, 0, sizeof(*state));

    state->func = func;
    state->in = in;
    state->flags = flags;
    state->status = THREAD_STATUS_PREPARING;
    state->pinned_to = NULL_CPU_ID;
    state->pin_refs = 0;

    state->mem_map = vmem_map_create();
    if(state->mem_map == NULL) {
        return -ENOMEM;
    }

    spinlock_init(&state->lock);

    int irq_flags = spin_lock_irq_save(&thread_tree_lock);

    get_thread_id(state);
    if(state->id == NULL_THREAD_ID) {
        // We somehow ran out of thread_id_t
        eprintk("thread_init: Ran out of unique thread_id_t!\n");
        vmem_map_destroy(state->mem_map);
        spin_unlock_irq_restore(&thread_tree_lock, irq_flags);
        return -ENOMEM;
    }


    ilist_node_t *node;
    ilist_for_each(node, &global_vmem_regions) {

        struct thread_global_vmem_region *global_region =
            container_of(node, struct thread_global_vmem_region, list_node);

        dprintk("Mapping global vmem region into thread (region virt-base = %p)\n", global_region->virtual_addr);
        res = vmem_map_map_region(state->mem_map, global_region->region, global_region->virtual_addr);
        if(res) {
            eprintk("thread_init: Failed to map in global thread vmem region at virtual address %p (err=%s)\n",
                    global_region->virtual_addr, errnostr(res));
            vmem_map_destroy(state->mem_map);
            return res;
        }
        dprintk("Mapped\n");

    }

    spin_unlock_irq_restore(&thread_tree_lock, irq_flags);

    res = arch_init_thread_state(state);
    if(res) {
        eprintk("arch_init_thread_state failed (err=%s)!\n",
                errnostr(res));
        vmem_map_destroy(state->mem_map);
        return res;
    }

    state->status = THREAD_STATUS_READY;

    return 0;
}

int
thread_deinit(
        struct thread_state *state)
{
    int res;

    int irq_flags = spin_lock_irq_save(&thread_tree_lock);
    struct ptree_node *rem = ptree_remove(&thread_tree, state->tree_node.key);
    DEBUG_ASSERT(rem == &state->tree_node);
    spin_unlock_irq_restore(&thread_tree_lock, irq_flags);

    res = arch_deinit_thread_state(state);
    if(res) {
        return res;
    }
    res = vmem_map_destroy(state->mem_map);
    if(res) {
        return res;
    }
    return 0;
}

// READY -> SCHEDULED transition
int
thread_schedule(struct thread_state *state)
{
    dprintk("thread_schedule(state=%p id=%ld)\n", state, state->id);

    int irq_flags = disable_save_irqs();

    if(state->flags & THREAD_FLAG_IDLE) {
        DEBUG_ASSERT(state->pinned_to == current_cpu_id());
        // If it's the idle thread, then we should have exclusive access
        enable_restore_irqs(irq_flags);
        irq_flags = spin_lock_irq_save(&state->lock);
    } else { 
        if(spin_try_lock(&state->lock)) {
            enable_restore_irqs(irq_flags);
            return -EBUSY;
        }
    }

    if(state->status != THREAD_STATUS_READY) {
        spin_unlock_irq_restore(&state->lock, irq_flags);
        return -EINVAL;
    }

    if(state->pin_refs && state->pinned_to != current_cpu_id()) {
        spin_unlock_irq_restore(&state->lock, irq_flags);
        eprintk("Tried to schedule thread %lld on CPU(%ld) but thread is pinned to CPU (%ld)\n",
                state->id, (sl_t)current_cpu_id(), (sl_t)state->pinned_to); 
        return -EINVAL;
    }

    state->status = THREAD_STATUS_SCHEDULED;

    spin_unlock_irq_restore(&state->lock, irq_flags);
    return 0;
}

static __attribute__((noreturn)) void 
__thread_switch_threadless(void *in)
{
    // We should be running with IRQ(s) disabled, and thus pinned to the current CPU
    struct thread_state *switching_from = current_thread();
    struct thread_state *switching_to = (struct thread_state *)in;

    DEBUG_ASSERT(KERNEL_ADDR(switching_to));

    // TIRED -> SLEEPING or RUNNING -> READY transition
    switch(switching_from->status) {
        case THREAD_STATUS_TIRED:
            switching_from->status = THREAD_STATUS_SLEEPING;
            break;
        case THREAD_STATUS_RUNNING:
            switching_from->status = THREAD_STATUS_READY;
            break;
        default:
            // This should be caught earlier
            panic("__thread_switch_threadless: switching from non-RUNNING or TIRED thread!\n");
            break;
    }

    // SCHEDULED -> RUNNING transition
    DEBUG_ASSERT(switching_to->status == THREAD_STATUS_SCHEDULED);
    switching_to->status = THREAD_STATUS_RUNNING;

    switching_to->running_on = current_cpu_id();
    dprintk("setting current_thread=%p\n", switching_to);
    *(struct thread_state **)percpu_ptr(percpu_addr(__current_thread)) = switching_to;
    DEBUG_ASSERT(current_thread() == switching_to);

    dprintk("activating vmem_map of new thread!\n");
    DEBUG_ASSERT(KERNEL_ADDR(switching_to->mem_map));
    vmem_map_activate(switching_to->mem_map);

    spin_unlock(&switching_from->lock);
    spin_unlock(&switching_to->lock);

    dprintk("running new thread\n");

    arch_thread_run_thread(switching_to);
    
    panic("Returned from arch_thread_run_thread!\n");
}

static __attribute__((noreturn)) void 
__thread_sleep_threadless(void *in)
{
    // We should be running with IRQ(s) disabled, and thus pinned to the current CPU
    struct thread_state *sleeping = current_thread();
    struct thread_state *switching_to = (struct thread_state *)in;

    sleeping->status = THREAD_STATUS_SLEEPING;
    switching_to->status = THREAD_STATUS_RUNNING;
    switching_to->running_on = current_cpu_id();
    dprintk("setting current_thread=%p\n", switching_to);
    *(struct thread_state **)percpu_ptr(percpu_addr(__current_thread)) = switching_to;
    DEBUG_ASSERT(current_thread() == switching_to);

    vmem_map_activate(switching_to->mem_map);

    spin_unlock(&sleeping->lock);
    spin_unlock(&switching_to->lock);

    arch_thread_run_thread(switching_to);
    
    panic("Returned from arch_thread_run_thread!\n");
}
int
thread_switch(struct thread_state *state)
{
    int res;

    struct thread_state *cur_thread;
    cur_thread = current_thread();

    int irq_flags = spin_lock_pair_irq_save(&cur_thread->lock, &state->lock);
    dprintk("thread_switch %p -> %p\n", cur_thread, state); 

    DEBUG_ASSERT(state->status == THREAD_STATUS_SCHEDULED);
    DEBUG_ASSERT(state->pin_refs == 0 || state->pinned_to == current_cpu_id());

    // This will unlock the locks
    if(cur_thread != NULL) {
        arch_thread_run_threadless(__thread_switch_threadless, state);
    } else {
        __thread_switch_threadless(state);
    }

    enable_restore_irqs(irq_flags);

    dprintk("Returned from thread switch (thread=%p)\n", current_thread());

    return 0;
}

int
thread_tire(struct thread_state *thread)
{
    int irq_flags = spin_lock_irq_save(&thread->lock);

    switch(thread->status) {
        case THREAD_STATUS_RUNNING:
            thread->status = THREAD_STATUS_TIRED;
            break;
        case THREAD_STATUS_READY:
            thread->status = THREAD_STATUS_SLEEPING;
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

    switch(thread->status) {
        case THREAD_STATUS_TIRED:
            thread->status = THREAD_STATUS_RUNNING;
            break;
        case THREAD_STATUS_SLEEPING:
            thread->status = THREAD_STATUS_READY;
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

/*
int
thread_switch(struct thread_state *state)
{
    int res;

    struct thread_state *cur_thread;
    cur_thread = *(struct thread_state**)percpu_ptr(percpu_addr(__current_thread));
    struct thread_state *to_restore = cur_thread;

    // We switch threads with IRQ(s) disabled
    int irq_flags = disable_save_irqs();

    spin_lock(&state->lock);
    switch(state->status) {
        case THREAD_STATUS_SCHEDULED:
            state->status = THREAD_STATUS_RUNNING;
            state->running_on = current_cpu_id();
            break;
        default:
            // Try to schedule the thread,
            spin_unlock(&state->lock);
            enable_restore_irqs(irq_flags);
            eprintk("Tried to switch to unscheduled thread!\n");
            return -EINVAL;
    }
    spin_unlock(&state->lock);
    
    // Weird state from the perspective of another CPU
    // (two threads claim to be running on the current CPU?)
    // but because interrupts are disabled, we should always
    // see ourselves as having a singular current thread, even if we can see
    // other CPU(s) in this weird limbo state

    spin_lock(&cur_thread->lock);

    switch(cur_thread->status) {
        case THREAD_STATUS_RUNNING:
            cur_thread->running_on = NULL_CPU_ID;
            cur_thread->status = THREAD_STATUS_READY;
            break;
        default:
            panic("thread_switch: current_thread->status != THREAD_STATUS_RUNNING");
    }

    // If we assume that all thread switches go through this function, then this isn't necessary,
    // but to be safe, we won't make that assumption for now, and possibly set the "current_thread"
    // more than is strictly necessary.
    *(struct thread_state **)percpu_ptr(percpu_addr(current_thread)) = state;

    spin_unlock(&cur_thread->lock);

    // From the perspective of another CPU we are now running the new thread,
    // even though we haven't actually changed our register state, stack, etc.

    res = arch_thread_switch(state, to_restore);

    // We are now back from running the other thread, restore our "current_thread" pointer
    *(struct thread_state **)percpu_ptr(percpu_addr(current_thread)) = to_restore;

    // Restore our IRQ state
    enable_restore_irqs(irq_flags);

    return res;
}
*/

__attribute__((noreturn))
void thread_abandon(struct thread_state *scheduled)
{
    int res;

    // We won't return, so we don't need to save the irq state
    disable_irqs();

    if(scheduled == NULL) {
        scheduled = idle_thread();
        res = thread_schedule(scheduled);
        if(res) {
            panic("Failed to schedule idle thread during thread_abandon(NULL)! (err=%s)\n",
                    errnostr(res));
        }
    }

    DEBUG_ASSERT(KERNEL_ADDR(scheduled));
    DEBUG_ASSERT(scheduled->status == THREAD_STATUS_SCHEDULED);
   
    struct thread_state *cur_thread = *(struct thread_state**)percpu_ptr(percpu_addr(__current_thread));

    DEBUG_ASSERT(KERNEL_ADDR(cur_thread));

    spin_lock(&cur_thread->lock);
    if(cur_thread->flags & THREAD_FLAG_IDLE) {
        panic("Tried to abandon CPU (%ld) idle thread!\n",
                (sl_t)current_cpu_id());
    }
    switch(cur_thread->status) {
        case THREAD_STATUS_RUNNING:
        case THREAD_STATUS_TIRED:
            cur_thread->status = THREAD_STATUS_ABANDONED;
            cur_thread->running_on = NULL_CPU_ID;
            break;
        default:
            panic("thread_abandon: switching from suspended thread!\n");
    }
    spin_unlock(&cur_thread->lock);

    spin_lock(&scheduled->lock);
    switch(scheduled->status) {
        case THREAD_STATUS_SCHEDULED:
            scheduled->status = THREAD_STATUS_RUNNING;
            scheduled->running_on = current_cpu_id();
            break;
        defualt:
            spin_unlock(&scheduled->lock);
            panic("CPU (%ld) new thread %p was not SCHEDULED during thread_abandon!\n",
                    (sl_t)current_cpu_id(), scheduled);
    }
    spin_unlock(&scheduled->lock);

    dprintk("setting current_thread=%p\n", scheduled);
    *(struct thread_state **)percpu_ptr(percpu_addr(__current_thread)) = scheduled;
    DEBUG_ASSERT(current_thread() == scheduled);

    dprintk("Abandoning thread %p for thread %p\n", cur_thread, scheduled);

    res = vmem_map_activate(scheduled->mem_map);
    if(res) {
        panic("Failed to activate new thread vmem_map during thread_abandon! (err=%s)\n",
                errnostr(res));
    }

    arch_thread_run_thread(scheduled);
}

__attribute__((noreturn))
void cpu_start_threading(thread_f *func, void *state)
{
    int res;

    // We won't return this this "thread" because it doesn't really exist, so we
    // can just leave IRQ(s) disabled
    disable_irqs();

    dprintk("cpu_start_threading (CPU %ld)\n", (sl_t)current_cpu_id());

    if(current_thread() != NULL) {
        while(1) {
        panic("Called cpu_start_threading() while current_thread() != NULL!\n");
        }
    }
    if(idle_thread() != NULL) {
        while(1) {
        panic("Called cpu_start_threading() while idle_thread() != NULL!\n");
        }
    }

    // Create the initial thread for this CPU
    struct thread_state *current = kmalloc(sizeof(struct thread_state));
    if(current == NULL) {
        panic("Ran out of memory during cpu_start_threading!\n");
    }
    
    res = thread_init(current, func, state, THREAD_FLAG_IDLE);
    if(res) {
        panic("Failed to create initial thread on CPU (%ld) (err=%s)\n",
                (long)current_cpu_id(), errnostr(res));
    }

    printk("Created initial thread on CPU (%ld)\n",
        (long)current_cpu_id());

    pin_thread_specific(current, current_cpu_id());

    // Our first thread on each core, must never return,
    // it must become our idle thread.
    struct thread_state **idle = percpu_ptr(percpu_addr(__idle_thread));
    *idle = current;

    spin_lock(&current->lock);
    current->status = THREAD_STATUS_RUNNING;
    current->running_on = current_cpu_id();
    dprintk("setting current_thread=%p\n", current);
    *(struct thread_state **)percpu_ptr(percpu_addr(__current_thread)) = current;
    DEBUG_ASSERT(current_thread() == current);
    spin_unlock(&current->lock);

    dprintk("cpu_start_threading: Activating Thread Virtual Memory Mapping\n");
    vmem_map_activate(current->mem_map);

    dprintk("cpu_start_threading: Running Initial Thread\n");
    arch_thread_run_thread(current);
}

static void
dump_thread_flags(struct thread_state *thread, unsigned long flags, printk_f *printer) {
    if(flags == 0) {
        return;
    }
    (*printer)(" ");
    if(flags & THREAD_FLAG_IDLE) {(*printer)("[IDLE]");}
    if(flags & THREAD_FLAG_PROCESS) {
        struct process *process =
            container_of(thread, struct process, thread);
        (*printer)("[PROCESS(%ld)]", (sl_t)process->id);
    }
}

int
dump_threads(printk_f *printer)
{
    int irq_flags = spin_lock_irq_save(&thread_tree_lock);

    (*printer)("--- Threads ---\n");
    struct ptree_node *node = ptree_get_first(&thread_tree);
    for(; node != NULL; node = ptree_get_next(node)) {
        struct thread_state *thread =
            container_of(node, struct thread_state, tree_node);
        (*printer)("\tThread(%ld): %s",
                (sl_t)thread->id,
                thread->status == THREAD_STATUS_RUNNING ? "RUNNING" :
                thread->status == THREAD_STATUS_SCHEDULED ? "SCHEDULED" :
                thread->status == THREAD_STATUS_READY ? "READY" :
                thread->status == THREAD_STATUS_TIRED ? "TIRED" :
                thread->status == THREAD_STATUS_SLEEPING ? "SLEEPING" :
                thread->status == THREAD_STATUS_PREPARING ? "PREPARING" :
                thread->status == THREAD_STATUS_ABANDONED ? "ABANDONED" :
                "ERROR-INVALID-STATUS");

        dump_thread_flags(thread, thread->flags, printer);

        if(thread->status == THREAD_STATUS_RUNNING) {
            (*printer)(" CPU(%ld)", (sl_t)thread->running_on);
        }
        if(thread->pin_refs) {
            (*printer)(" PINNED(%ld) PIN-REFS(%ld)", (sl_t)thread->pinned_to, (sl_t)thread->pin_refs);
        }

        (*printer)("\n");
    }
    (*printer)("---------------\n");

    spin_unlock_irq_restore(&thread_tree_lock, irq_flags);
    return 0;
}

static int
global_vmem_region_slab_alloc_static_init(void) {
    if(global_vmem_region_slab_allocator != NULL) {
        return -EINVAL;
    }

    global_vmem_region_slab_allocator =
        create_static_slab_allocator(
                global_vmem_regions_slab_buffer,
                GLOBAL_VMEM_REGIONS_SLAB_BUFFER_SIZE, 
                sizeof(struct thread_global_vmem_region),
                orderof(struct thread_global_vmem_region));
    if(global_vmem_region_slab_allocator == NULL) {
        return -ENOMEM;
    }

    return 0;
}
declare_init(static, global_vmem_region_slab_alloc_static_init);

static struct thread_global_vmem_region *
alloc_thread_global_vmem_region(void) {
    struct thread_global_vmem_region *region = slab_alloc(global_vmem_region_slab_allocator);
    dprintk("alloc_thread_global_vmem_region() -> %p (list_node=%p)\n", &region, &region->list_node);
    return region;
}

static void
free_thread_global_vmem_region(struct thread_global_vmem_region *region) {
    dprintk("free_thread_global_vmem_region() -> %p (list_node=%p)\n", &region, &region->list_node);
    slab_free(global_vmem_region_slab_allocator, region);
}

static void
thread_force_mapping_visitor(struct ptree_node *node, void *state)
{
    struct thread_state *thread = container_of(node, struct thread_state, tree_node);
    struct thread_global_vmem_region *global_region = state;

    int res = vmem_map_map_region(thread->mem_map, global_region->region, global_region->virtual_addr);
    if(res) {
        eprintk("thread_force_mapping_visitor: Failed to map region into thread %p (err=%s)\n",
                thread, errnostr(res));
    }
}

int
thread_force_mapping(
        struct vmem_region *region,
        vaddr_t virtual_addr)
{
    int res;

    dprintk("Thread Force Mapping [%p-%p) -> %p\n",
            virtual_addr, virtual_addr + region->size, region);

    int irq_flags = spin_lock_irq_save(&thread_tree_lock);

    struct thread_global_vmem_region *global_region =
        alloc_thread_global_vmem_region();
    if(region == NULL) {
        spin_unlock_irq_restore(&thread_tree_lock, irq_flags);
        return -ENOMEM;
    }
    memset(global_region, 0, sizeof(struct thread_global_vmem_region));

    global_region->region = region;
    global_region->virtual_addr = virtual_addr;

    ptree_for_each(&thread_tree, thread_force_mapping_visitor, global_region);

    ilist_push_tail(&global_vmem_regions, &global_region->list_node);

    spin_unlock_irq_restore(&thread_tree_lock, irq_flags);

    return 0;
}

int
thread_relax_mapping(vaddr_t virtual_addr)
{
    return -EUNIMPL;
}

// Testing

//static void
//thread_test_thread_switch(void *in)
//{
//    printk("thread_test_thread_switch (current_thread=%p)\n",
//            current_thread());
//
//    struct thread_state *next_thread = in;
//    int res = thread_schedule(next_thread);
//    if(res) {
//        eprintk("thread_test_thread_switch: Failed to schedule next thread! (err=%s)\n",
//                errnostr(res));
//    }
//    thread_switch(next_thread);
//}
//
//static void
//thread_test_thread_abandon(void *in)
//{
//    printk("thread_test_thread_abandon (current_thread=%p)\n",
//            current_thread());
//
//    struct thread_state *next_thread = in;
//    int res = thread_schedule(next_thread);
//    if(res) {
//        eprintk("thread_test_thread_abandon: Failed to schedule next thread! (err=%s)\n",
//                errnostr(res));
//    }
//    thread_abandon(next_thread);
//}
//
//static int
//thread_test(void)
//{
//    int res;
//
//    struct thread_state thread_1;
//    struct thread_state thread_2;
//
//    int irq_flags = disable_save_irqs();
//
//    res = thread_init(
//            &thread_1,
//            thread_test_thread_switch,
//            current_thread(),
//            0);
//    if(res) {
//        enable_restore_irqs(irq_flags);
//        return res;
//    }
//
//    res = thread_init(
//            &thread_2,
//            thread_test_thread_abandon,
//            current_thread(),
//            0);
//    if(res) {
//        enable_restore_irqs(irq_flags);
//        return res;
//    }
//
//    printk("Scheduling thread1\n");
//    res = thread_schedule(&thread_1);
//    if(res) {
//        enable_restore_irqs(irq_flags);
//        return res;
//    }
//    printk("Switching to thread1\n");
//    res = thread_switch(&thread_1);
//    if(res) {
//        enable_restore_irqs(irq_flags);
//        return res;
//    }
//    printk("Returned from thread1\n");
//
//    printk("Scheduling thread2\n");
//    res = thread_schedule(&thread_2);
//    if(res) {
//        enable_restore_irqs(irq_flags);
//        return res;
//    }
//    printk("Switching to thread2\n");
//    res = thread_switch(&thread_2);
//    if(res) {
//        enable_restore_irqs(irq_flags);
//        return res;
//    }
//    printk("Returned from thread2\n");
//
//    if(thread_1.status != THREAD_STATUS_READY)
//    {
//        eprintk("thread_test FAIL: thread_1 is not ready!\n");
//        return -EINVAL;
//    }
//    if(thread_2.status != THREAD_STATUS_ABANDONED)
//    {
//        eprintk("thread_test FAIL: thread_2 was not abandoned!\n");
//        return -EINVAL;
//    }
//
//    thread_deinit(&thread_1);
//    thread_deinit(&thread_2);
//
//    enable_restore_irqs(irq_flags);
//    return 0;
//}
//declare_init_desc(smp, thread_test, "Running Thread Test(s)");

