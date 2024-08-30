
#include <kanawha/thread.h>
#include <kanawha/printk.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>
#include <kanawha/string.h>
#include <kanawha/percpu.h>
#include <kanawha/init.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/atomic.h>
#include <kanawha/scheduler.h>
#include <kanawha/vmem.h>
#include <kanawha/slab.h>

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
        struct ptree_node *node = ptree_get(&thread_tree, id);
        if(node == NULL) {
            state->id = id;
            ptree_insert(&thread_tree, &state->tree_node, state->id);
            return;
        }
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
    dprintk("Entered Idle Thread On CPU %d\n", current_cpu_id());

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
        if(thread->status == THREAD_STATUS_RUNNING) {
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
    state->status = THREAD_STATUS_SUSPEND;
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

    return 0;
}

int
thread_deinit(
        struct thread_state *state)
{
    int res;
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

int
thread_schedule(struct thread_state *state)
{
    dprintk("thread_schedule\n");
    int irq_flags = spin_lock_irq_save(&state->lock);

    if(state->status != THREAD_STATUS_SUSPEND) {
        spin_unlock_irq_restore(&state->lock, irq_flags);
        return -EINVAL;
    }

    if(state->pin_refs && state->pinned_to != current_cpu_id()) {
        spin_unlock_irq_restore(&state->lock, irq_flags);
        eprintk("Tried to schedule thread %p on CPU(%ld) but thread is pinned to CPU (%ld)\n",
                state, (sl_t)current_cpu_id(), (sl_t)state->pinned_to); 
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

    switching_from->status = THREAD_STATUS_SUSPEND;
    switching_to->status = THREAD_STATUS_RUNNING;
    switching_to->running_on = current_cpu_id();
    *(struct thread_state **)percpu_ptr(percpu_addr(__current_thread)) = switching_to;

    vmem_map_activate(switching_to->mem_map);

    spin_unlock(&switching_to->lock);
    spin_unlock(&switching_from->lock);

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

    if(state->status != THREAD_STATUS_SCHEDULED ||
       ((state->pin_refs > 0) && state->pinned_to != current_cpu_id()))
    {
        spin_unlock_pair_irq_restore(&cur_thread->lock, &state->lock, irq_flags);
        return -EINVAL;
    }

    // This will unlock the locks
    void *ret_ptr;
    if(cur_thread != NULL) {
        arch_thread_run_threadless(__thread_switch_threadless, state);
    } else {
        __thread_switch_threadless(state);
    }

    enable_restore_irqs(irq_flags);

    res = (int)(uintptr_t)ret_ptr;
    if(res) {
        return res;
    }
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
            cur_thread->status = THREAD_STATUS_SUSPEND;
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
    }
   
    struct thread_state *cur_thread = *(struct thread_state**)percpu_ptr(percpu_addr(__current_thread));

    spin_lock(&cur_thread->lock);
    if(cur_thread->flags & THREAD_FLAG_IDLE) {
        panic("Tried to abandon CPU (%ld) idle thread!\n",
                (sl_t)current_cpu_id());
    }
    switch(cur_thread->status) {
        case THREAD_STATUS_RUNNING:
            cur_thread->status = THREAD_STATUS_ABANDONED;
            cur_thread->running_on = NULL_CPU_ID;
            break;
        default:
            panic("thread_abandon: switching from thread with status != THREAD_STATUS_RUNNING!\n");
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

    *(struct thread_state **)percpu_ptr(percpu_addr(__current_thread)) = scheduled;

    dprintk("Abandoning thread %p for thread %p\n", cur_thread, scheduled);

    vmem_map_activate(scheduled->mem_map);

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

    dprintk("Created initial thread on CPU (%ld)\n",
        (long)current_cpu_id());

    pin_thread_specific(current, current_cpu_id());

    // Our first thread on each core, must never return,
    // it must become our idle thread.
    struct thread_state **idle = percpu_ptr(percpu_addr(__idle_thread));
    *idle = current;

    spin_lock(&current->lock);
    current->status = THREAD_STATUS_RUNNING;
    current->running_on = current_cpu_id();
    *(struct thread_state **)percpu_ptr(percpu_addr(__current_thread)) = current;
    spin_unlock(&current->lock);

    dprintk("cpu_start_threading: Activating Thread Virtual Memory Mapping\n");
    vmem_map_activate(current->mem_map);

    arch_thread_run_thread(current);
}

static void
dump_thread_flags(unsigned long flags, printk_f *printer) {
    if(flags == 0) {
        return;
    }
    (*printer)(" ");
    if(flags & THREAD_FLAG_IDLE) {(*printer)("[IDLE]");}
    if(flags & THREAD_FLAG_USER) {(*printer)("[USER]");}
    if(flags & THREAD_FLAG_PROCESS) {(*printer)("[PROCESS]");}
}

int
dump_threads(printk_f *printer)
{
    int irq_state = disable_save_irqs();
    spin_lock(&thread_tree_lock);
    (*printer)("--- Threads ---\n");
    struct ptree_node *node = ptree_get_first(&thread_tree);
    for(; node != NULL; node = ptree_get_next(node)) {
        struct thread_state *thread =
            container_of(node, struct thread_state, tree_node);
        (*printer)("\tThread(%ld): %s",
                (sl_t)thread->id,
                thread->status == THREAD_STATUS_RUNNING ? "RUNNING" :
                thread->status == THREAD_STATUS_SCHEDULED ? "SCHEDULED" :
                thread->status == THREAD_STATUS_SUSPEND ? "SUSPEND" :
                thread->status == THREAD_STATUS_ABANDONED ? "ABANDONED" :
                "ERROR-INVALID-STATUS");

        dump_thread_flags(thread->flags, printer);

        if(thread->status == THREAD_STATUS_RUNNING) {
            (*printer)(" CPU(%ld)", (sl_t)thread->running_on);
        }
        if(thread->pin_refs) {
            (*printer)(" PINNED(%ld) PIN-REFS(%ld)", (sl_t)thread->pinned_to, (sl_t)thread->pin_refs);
        }
        (*printer)("\n");
    }
    (*printer)("---------------\n");
    spin_unlock(&thread_tree_lock);
    enable_restore_irqs(irq_state);
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

