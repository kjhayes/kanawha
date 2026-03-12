#ifndef __KANAWHA__SCHEDULER_H__
#define __KANAWHA__SCHEDULER_H__

#include <kanawha/ops.h>
#include <kanawha/printk.h>
#include <kanawha/stree.h>
#include <kanawha/thread.h>

// Asking if we should resched
#define SCHED_SOFT_RESCHED_SIG(RET, ARG, ...) \
    RET(int)

// Telling we need to be resched (sleeping, waiting, exiting, etc.)
#define SCHED_HARD_RESCHED_SIG(RET, ARG, ...) \
    RET(int)

#define SCHED_ADD_THREAD_SIG(RET, ARG, ...)                                    \
    RET(int)                                                                   \
    ARG(struct thread_state *, thread)

#define SCHED_REMOVE_THREAD_SIG(RET, ARG, ...)                                 \
    RET(int)                                                                   \
    ARG(struct thread_state *, thread)

#define SCHED_DEBUG_DUMP_SIG(RET, ARG, ...)                                    \
    RET(int)                                                                   \
    ARG(printk_f *, printer)

#define SCHED_OP_LIST(OP, ...)                                                 \
    OP(soft_resched, SCHED_SOFT_RESCHED_SIG, ##__VA_ARGS__)                  \
    OP(hard_resched, SCHED_HARD_RESCHED_SIG, ##__VA_ARGS__)                  \
    OP(add_thread, SCHED_ADD_THREAD_SIG, ##__VA_ARGS__)                        \
    OP(remove_thread, SCHED_REMOVE_THREAD_SIG, ##__VA_ARGS__)                  \
    OP(debug_dump, SCHED_DEBUG_DUMP_SIG, ##__VA_ARGS__)

#define SCHED_TYPE_ALLOC_INSTANCE_SIG(RET, ARG, ...) RET(struct scheduler *)

#define SCHED_TYPE_FREE_INSTANCE_SIG(RET, ARG, ...)                            \
    RET(int)                                                                   \
    ARG(struct scheduler *, instance)

#define SCHED_TYPE_OP_LIST(OP, ...)                                            \
    OP(alloc_instance, SCHED_TYPE_ALLOC_INSTANCE_SIG, ##__VA_ARGS__)           \
    OP(free_instance, SCHED_TYPE_FREE_INSTANCE_SIG, ##__VA_ARGS__)

struct scheduler;

struct scheduler_type
{
    const char *name;
    ilist_t instance_list;
    struct stree_node tree_node;

    struct
    {
        DECLARE_OP_LIST_PTRS(SCHED_OP_LIST, struct scheduler *);
    } instance_ops;

    struct
    {
        DECLARE_OP_LIST_PTRS(SCHED_TYPE_OP_LIST, struct scheduler_type *);
    } type_ops;
};

#define SCHED_TYPE_OPS_ACCESSOR(__self, __field) __self->type_ops.__field

DEFINE_OP_LIST_WRAPPERS(SCHED_TYPE_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        scheduler_type,
                        SCHED_TYPE_OPS_ACCESSOR,
                        SELF_ACCESSOR);

struct scheduler
{
    struct scheduler_type *type;

    // Fields managed by higher level scheduler API
    spinlock_t lock;
    size_t num_cpus;
    char *name;
    ilist_node_t instance_list_node;
};

#define SCHED_INSTANCE_OPS_ACCESSOR(__self, __field)                           \
    __self->type->instance_ops.__field

DEFINE_OP_LIST_WRAPPERS(SCHED_OP_LIST,
                        static inline,
                        /* No Prefix */,
                        scheduler,
                        SCHED_INSTANCE_OPS_ACCESSOR,
                        SELF_ACCESSOR);

#undef SCHED_NEXT_SIG
#undef SCHED_OP_LIST

int
register_scheduler_type(struct scheduler_type *type);

struct scheduler *
create_scheduler(const char *type_name, const char *sched_name);

int
assign_cpu_scheduler(struct scheduler *sched, cpu_id_t cpu);

// Assumes preemption is disabled
// Returns NULL if the current CPU does not have a scheduler
struct scheduler *
current_sched(void);

// Allow the scheduler to reschedule
// the current thread (may not actually)
int soft_resched(void);

// Force the scheduler to reschedule
// the current thread (even if that means
// switching to the idle thread)
int hard_resched(void);

// Default Implementations
int
sched_debug_dump_no_info(struct scheduler *sched, printk_f *printer);

// Debug Printing
void
dump_schedulers(printk_f *printer);

#endif
