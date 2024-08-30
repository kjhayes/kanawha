#ifndef __KANAWHA__SCHEDULER_H__
#define __KANAWHA__SCHEDULER_H__

#include <kanawha/thread.h>
#include <kanawha/stree.h>
#include <kanawha/ops.h>

// Asking if we should resched
#define SCHED_QUERY_RESCHED_SIG(RET,ARG)\
RET(struct thread_state *)

// Telling we need to be resched (sleeping, waiting, exiting, etc.)
#define SCHED_FORCE_RESCHED_SIG(RET,ARG)\
RET(struct thread_state *)

#define SCHED_ADD_THREAD_SIG(RET,ARG)\
RET(int)\
ARG(struct thread_state *, thread)

#define SCHED_REMOVE_THREAD_SIG(RET,ARG)\
RET(int)\
ARG(struct thread_state *, thread)

#define SCHED_OP_LIST(OP, ...)\
OP(query_resched, SCHED_QUERY_RESCHED_SIG, ##__VA_ARGS__)\
OP(force_resched, SCHED_FORCE_RESCHED_SIG, ##__VA_ARGS__)\
OP(add_thread, SCHED_ADD_THREAD_SIG, ##__VA_ARGS__)\
OP(remove_thread, SCHED_REMOVE_THREAD_SIG, ##__VA_ARGS__)\

#define SCHED_TYPE_ALLOC_INSTANCE_SIG(RET,ARG)\
RET(struct scheduler *)

#define SCHED_TYPE_FREE_INSTANCE_SIG(RET,ARG)\
RET(int)\
ARG(struct scheduler *, instance)

#define SCHED_TYPE_OP_LIST(OP, ...)\
OP(alloc_instance, SCHED_TYPE_ALLOC_INSTANCE_SIG, ##__VA_ARGS__)\
OP(free_instance, SCHED_TYPE_FREE_INSTANCE_SIG, ##__VA_ARGS__)

struct scheduler;

struct scheduler_type
{
    const char *name;
    ilist_t instance_list;
    struct stree_node tree_node;

    struct {
DECLARE_OP_LIST_PTRS(SCHED_OP_LIST, struct scheduler *);
    } instance_ops;

    struct {
DECLARE_OP_LIST_PTRS(SCHED_TYPE_OP_LIST, struct scheduler_type *);
    } type_ops;
};

DEFINE_OP_LIST_WRAPPERS(
        SCHED_TYPE_OP_LIST,
        static inline,
        /* No Prefix */,
        scheduler_type,
        ->type_ops.,
        SELF_ACCESSOR);

struct scheduler
{
    struct scheduler_type *type;

    spinlock_t lock;
    size_t num_cpus;
};

DEFINE_OP_LIST_WRAPPERS(
    SCHED_OP_LIST,
    static inline,
    /* No Prefix */,
    scheduler,
    ->type->instance_ops.,
    SELF_ACCESSOR);

#undef SCHED_NEXT_SIG
#undef SCHED_OP_LIST

int
register_scheduler_type(struct scheduler_type *type);

struct scheduler *
create_scheduler(const char *type_name);

int
assign_cpu_scheduler(
        struct scheduler *sched,
        cpu_id_t cpu);

// Assumes preemption is disabled
// Returns NULL if the current CPU does not have a scheduler
struct scheduler *
current_sched(void);

struct thread_state * query_resched(void);
struct thread_state * force_resched(void);

#endif
