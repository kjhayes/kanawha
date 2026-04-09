#ifndef __KANAWHA__THREAD_H__
#define __KANAWHA__THREAD_H__

#include <kanawha/attribute.h>
#include <kanawha/cpu.h>
#include <kanawha/percpu.h>
#include <kanawha/printk.h>
#include <kanawha/ptree.h>
#include <kanawha/spinlock.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>

#if defined(CONFIG_X64)
#include <arch/x64/thread.h>
#elif CONFIG_RISCV64
#include <arch/riscv64/thread.h>
#else
#error "Architecture has not declared header: thread.h!"
#endif

typedef long thread_id_t;
#define NULL_THREAD_ID (thread_id_t)(-1)

typedef void(thread_f)(void *in);
typedef __noreturn void(threadless_f)(void *in);

/*
 * Valid THREAD_STATUS Transitions
 *
 * // thread_schedule
 * READY -> SCHEDULED
 *
 * // thread_switch or thread_abandon (to the argument)
 * SCHEDULED -> RUNNING // done on thread switch
 *
 * // thread_switch (to the current thread)
 * RUNNING -> READY
 * TIRED -> SLEEPING
 *
 * // thread_abandon (to the current thread)
 * RUNNING -> ABANDONED
 *
 * // thread_tire
 * RUNNING -> TIRED
 * READY -> SLEEPING
 *
 * // thread_wake
 * TIRED -> RUNNING
 * SLEEPING -> READY
 *
 */

typedef enum {
    // Still in the process of being created
    THREAD_STATUS_PREPARING = 0,

    // Not currently running but may be scheduled
    THREAD_STATUS_READY,
    // (transition stage from READY -> RUNNING)
    THREAD_STATUS_SCHEDULED,

    // Currently running on some processor
    THREAD_STATUS_RUNNING,

    // Currently running, will go to sleep on next thread switch
    THREAD_STATUS_TIRED,

    // Sleeping cannot be scheduled
    THREAD_STATUS_SLEEPING,

    // Can never be run again without reinitialization
    THREAD_STATUS_ABANDONED,
} thread_status_t;

#define NUM_THREAD_STATUSES (THREAD_STATUS_ABANDONED+1)

#define THREAD_FLAG_IDLE (1ULL << 0)
#define THREAD_FLAG_PROCESS (1ULL << 1)
#define THREAD_FLAG_TASKLET (1ULL << 2)

struct thread_state
{
    struct arch_thread_state arch_state;

    spinlock_t lock;
    struct ptree_node tree_node;

    struct waitqueue *waitqueue;
    ilist_node_t waitqueue_node;

    struct thread_state *scheduled;

    thread_id_t id;
    thread_f *func;

    cpu_id_t running_on;

    cpu_id_t pinned_to;
    size_t pin_refs;

    void *in;

    struct vmem_map *mem_map;

    int irq_depth;

    unsigned long flags;
    thread_status_t status;

    struct {
        time_t creation_timestamp;
        time_t last_scheduled_timestamp;
        time_t last_unscheduled_timestamp;

        duration_t back_duration;
        duration_t back_runtime;
        time_t front_start;
        duration_t front_runtime;

    } timing;
};

int
thread_init(struct thread_state *state,
            thread_f *func,
            void *in,
            unsigned long flags);

int
thread_deinit(struct thread_state *state);

// Assumes preemption is already disabled
struct thread_state *
current_thread(void);

static inline int
current_thread_is_rescheduled(void)
{
    struct thread_state *scheduled = current_thread()->scheduled;
    if(scheduled == NULL)
    {
        return 0;
    }
    DEBUG_ASSERT(KERNEL_ADDR(scheduled));
    DEBUG_ASSERT(scheduled->status == THREAD_STATUS_SCHEDULED);
    return 1;
}

// Ensure that this thread does not change CPU(s)
int
pin_thread(struct thread_state *thread);
int
unpin_thread(struct thread_state *thread);

int
pin_thread_specific(struct thread_state *thread, cpu_id_t cpu);

// Assumes preemption is already disabled
// Returns NULL if the idle thread has not been created on the current CPU
struct thread_state *
idle_thread(void);

// Gets the idle_thread of any CPU
struct thread_state *
cpu_idle_thread(cpu_id_t cpu);

// To be called from within a scheduler, checks to make sure that a thread
// can be run on the current processor, and changes the threads status
// to THREAD_STATUS_SCHEDULED atomically.
//
// It then associates "to_schedule" with the current
// thread, so that even if the current thread is interrupted
// between calling thread schedule, and actually switching threads,
// "to_schedule" should always be the next thread which runs
// on the CPU.
//
// Returns 0 on success, else, Returns negative errno
int
thread_schedule(struct thread_state *to_schedule);

// Transition the current thread from "RUNNING" to "TIRED"
// or "READY" to "SLEEPING"
//
// Does nothing if the thread is already "TIRED" or "SLEEPING"
//
// Returns 0 on success, else, Returns negative errno
int
thread_tire(struct thread_state *thread);

// Same as thread_tire but provide a format string and arguments which
// can be used to generate a "reason" message for debugging
int
thread_tire_with_reason(struct thread_state *state, const char *fmt, ...);

// Does the opposite of thread_tire, going from "TIRED" to "RUNNING"
// or "SLEEPING" to "READY"
//
// Returns 0 on success, else, Returns negative errno
int
thread_wake(struct thread_state *thread);

// Switch to the scheduled thread, saving the state of the calling thread
// (returns negative errno if we fail to switch threads at all)
int
thread_switch(void);

// Abandon the current thread and begin running
// a thread which was previously scheduled via
// calling "thread_schedule",
// making it impossible to safely return to running
// the current thread.
//
// If no thread has been scheduled, it will begin running the idle thread
// on the current CPU
__noreturn void
thread_abandon(void);

// Start threading on the current CPU (assumes preemption is disabled)
__noreturn void
cpu_start_threading(thread_f *func, void *state);

int
arch_init_thread_state(struct thread_state *thread);
int
arch_deinit_thread_state(struct thread_state *thread);

// If we have a current thread, we need to checkpoint it, and then run "func"
// without a thread, this may block, as "func" could switch from "threadless"
// to running a different thread
//
// From the perspective of the calling thread, this should run normally,
// but really what must happen is the thread will have all of it's state saved,
// such that when "arch_thread_run_thread" is next called on the thread,
// it will be restored as if it just returned from the call to
// "arch_thread_become_threadless"
void
arch_thread_run_threadless(threadless_f *func, void *in);

// Restore the state of "to_run" and begin executing it
// (Does not save state, so it should be run from a "threadless" context
__noreturn void
arch_thread_run_thread(struct thread_state *to_run);

int
arch_dump_thread(printk_f *printer, struct thread_state *state);

int
dump_threads(printk_f *printer);

__noreturn void
idle_loop(void);

// Global Thread Virtual Memory Regions

// Forces "region" to be mapped in a virtual_addr in every thread's virtual
// address space. This is can be done lazily, but after returning (and
// synchronization if we are a multiprocessor), then any thread which is
// running should be able to access "region" at virtual_addr safely.
int
thread_force_mapping(struct vmem_region *region, void *virtual_addr);

// Stops forcing the vmem region containing "virtual_addr" to
// be mapped in all threads, (does not undo the mapping in
// threads which contain it already though)
int
thread_relax_mapping(void *virtual_addr);

DECLARE_EXTERN_PERCPU_VAR(struct thread_state *, __current_thread);

const char *
thread_status_to_string(thread_status_t status);

static inline void
thread_begin_irq(void) {
    struct thread_state *cur = current_thread();
    if(cur) {
        cur->irq_depth++;
    }
}

static inline void
thread_end_irq(void) {
    struct thread_state *cur = current_thread();
    if(cur) {
        cur->irq_depth--;
    }
}

static inline int
thread_irq_depth(void) {
    struct thread_state *cur = current_thread();
    if(cur) {
        return cur->irq_depth;
    }
    return 0; // Assume we are not in an IRQ if we do not have a thread.
}

// Read the current runtime sample for
// this thread (runtime -> duration that this thread has
//                         been running for
//              sample_length -> length of the current sample)
int
thread_get_runtime(
        struct thread_state *thread,
        duration_t *runtime,
        duration_t *sample_length);

// >=0 -> percent of current same period this thread
//        has been running
// <0 -> errno value
ssize_t
thread_get_running_percentage(
        struct thread_state *thread);

ssize_t threads_total_running_percentage(void);

size_t
thread_status_count(
        thread_status_t status);


#endif
