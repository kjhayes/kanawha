#ifndef __KANAWHA__THREAD_H__
#define __KANAWHA__THREAD_H__

#include <kanawha/stdint.h>
#include <kanawha/spinlock.h>
#include <kanawha/ptree.h>
#include <kanawha/printk.h>
#include <kanawha/cpu.h>
#include <kanawha/vmem.h>

#ifdef CONFIG_X64
#include <arch/x64/thread.h>
#else
#error "Architecture has not declared header: thread.h!"
#endif

typedef long thread_id_t;
#define NULL_THREAD_ID (thread_id_t)(-1)

typedef void(thread_f)(void *in);
typedef __attribute__((noreturn)) void(threadless_f)(void *in);

typedef uint32_t thread_status_t;

#define THREAD_STATUS_SUSPEND   0
#define THREAD_STATUS_SCHEDULED 1
#define THREAD_STATUS_RUNNING   2
#define THREAD_STATUS_ABANDONED 3

#define THREAD_FLAG_IDLE    (1ULL<<0)
#define THREAD_FLAG_PROCESS (1ULL<<1)

struct thread_state
{
    struct arch_thread_state arch_state;

    spinlock_t lock;
    struct ptree_node tree_node;

    thread_id_t id;
    thread_f *func;

    cpu_id_t running_on;

    cpu_id_t pinned_to;
    size_t pin_refs;

    void * in;

    struct vmem_map *mem_map;

    unsigned long flags;
    thread_status_t status;
};

int
thread_init(
        struct thread_state *state,
        thread_f *func,
        void *in,
        unsigned long flags);

int
thread_deinit(
        struct thread_state *state);

// Assumes preemption is already disabled
struct thread_state *current_thread(void);

// Ensure that this thread does not change CPU(s)
int
pin_thread(struct thread_state *thread);
int
unpin_thread(struct thread_state *thread);

int
pin_thread_specific(
        struct thread_state *thread,
        cpu_id_t cpu);

// Assumes preemption is already disabled
// Returns NULL if the idle thread has not been created on the current CPU
struct thread_state *idle_thread(void);

// To be called from within a scheduler, checks to make sure that a thread
// can be run on the current processor, and changes the threads status
// to THREAD_STATUS_SCHEDULED atomically.
//
// Returns 0 on success, else, Returns negative errno
int thread_schedule(struct thread_state *to_schedule);

// Switch to a scheduled thread, saving the state of the calling thread
// (returns negative errno if we fail to switch threads at all)
int thread_switch(struct thread_state *scheduled);

// Abandon the current thread and begin running
// "scheduled", making it impossible to safely return to running
// the current thread.
//
// If "scheduled == NULL", then we will begin running the current CPU's
// idle thread.
__attribute__((noreturn))
void thread_abandon(struct thread_state *scheduled);

// Start threading on the current CPU (assumes preemption is disabled)
__attribute__((noreturn))
void cpu_start_threading(thread_f *func, void *state);

int arch_init_thread_state(struct thread_state *thread);
int arch_deinit_thread_state(struct thread_state *thread);

// Should eventually return zero when we return to "from"
// The architecture also needs to atomically set "from"'s status from
// "Running" to "Suspended" once the switch is complete,
// ("to" should already be marked as "Running")
int arch_thread_switch(struct thread_state *to, struct thread_state *from);

// If we have a current thread, we need to checkpoint it, and then run "func"
// without a thread, this may block, as "func" could switch from "threadless"
// to running a different thread
// 
// From the perspective of the calling thread, this should run normally,
// but really what must happen is the thread will have all of it's state saved,
// such that when "arch_thread_run_thread" is next called on the thread,
// it will be restored as if it just returned from the call to "arch_thread_become_threadless"
void arch_thread_run_threadless(threadless_f *func, void *in);

// Restore the state of "to_run" and begin executing it
// (Does not save state, so it should be run from a "threadless" context
__attribute__((noreturn))
void arch_thread_run_thread(struct thread_state *to_run);

int
arch_dump_thread(printk_f *printer, struct thread_state *state);

int
dump_threads(printk_f *printer);

__attribute__((noreturn))
void
idle_loop(void);

// Global Thread Virtual Memory Regions

// Forces "region" to be mapped in a virtual_addr in every thread's virtual address
// space. This is can be done lazily, but after returning (and synchronization if
// we are a multiprocessor), then any thread which is running should be able to access
// "region" at virtual_addr safely.
int
thread_force_mapping(struct vmem_region *region, vaddr_t virtual_addr);

// Stops forcing the vmem region containing "virtual_addr" to
// be mapped in all threads, (does not undo the mapping in
// threads which contain it already though)
int
thread_relax_mapping(vaddr_t virtual_addr);

#endif
