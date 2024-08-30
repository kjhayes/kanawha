
#include <kanawha/scheduler.h>
#include <kanawha/spinlock.h>
#include <kanawha/stree.h>
#include <kanawha/stddef.h>
#include <kanawha/percpu.h>
#include <kanawha/string.h>
#include <kanawha/init.h>

static DECLARE_SPINLOCK(sched_type_tree_lock);
static DECLARE_STREE(sched_type_tree);

DECLARE_STATIC_PERCPU_VAR(struct scheduler *, current_scheduler);

int
register_scheduler_type(
        struct scheduler_type *type)
{
    printk("Registering Scheduler Type: \"%s\"\n", type->name);

    spin_lock(&sched_type_tree_lock);
    struct stree_node *node = stree_get(&sched_type_tree, type->name);
    if(node != NULL) {
        spin_unlock(&sched_type_tree_lock);
        eprintk("Scheduler with name \"%s\" has already been registered!\n");
        return -EEXIST;
    }

    type->tree_node.key = type->name;
    stree_insert(&sched_type_tree, &type->tree_node);

    ilist_init(&type->instance_list);

    spin_unlock(&sched_type_tree_lock);

    return 0;
}

struct scheduler *
create_scheduler(const char *type_name)
{
    struct scheduler_type *type;
    spin_lock(&sched_type_tree_lock);
    struct stree_node *type_node = stree_get(&sched_type_tree, type_name);
    if(type_node == NULL) {
        spin_unlock(&sched_type_tree_lock);
        return NULL;
    }
    type = container_of(
            type_node, struct scheduler_type, tree_node);
    spin_unlock(&sched_type_tree_lock);

    struct scheduler *sched = scheduler_type_alloc_instance(type);
    if(sched == NULL) {
        return sched;
    }

    sched->num_cpus = 0;
    sched->type = type;
    spinlock_init(&sched->lock);

    return sched;
}

int
assign_cpu_scheduler(
        struct scheduler *sched,
        cpu_id_t cpu)
{
    struct scheduler *existing = *(struct scheduler**)percpu_ptr_specific(percpu_addr(current_scheduler), cpu);
    if(existing == sched) {
        return 0;
    }

    if(existing != NULL) {
        // The locking here is questionable
        int flags = spin_lock_pair_irq_save(&existing->lock, &sched->lock);
        existing->num_cpus--;
        sched->num_cpus++;
        (*(struct scheduler **)percpu_ptr_specific(percpu_addr(current_scheduler), cpu)) = sched;
        spin_unlock_pair_irq_restore(&existing->lock, &sched->lock, flags);

    } else {
        int flags = spin_lock_irq_save(&sched->lock);
        sched->num_cpus++;
        (*(struct scheduler **)percpu_ptr_specific(percpu_addr(current_scheduler), cpu)) = sched;
        spin_unlock_irq_restore(&sched->lock, flags);
    }

    return 0;
}

struct scheduler *
current_sched(void) {
    return *(struct scheduler**)percpu_ptr(percpu_addr(current_scheduler));
}

static int
init_cpu_scheds(void) {
    // Clear every CPU(s) scheduler to a NULL value
    for(cpu_id_t cpu = 0; cpu < total_num_cpus(); cpu++) {
        *(struct scheduler**)percpu_ptr_specific(percpu_addr(current_scheduler), cpu) = NULL;
    }

    // If we have a default scheduler, create an instance, and assign it to every CPU
    if(strlen(CONFIG_DEFAULT_SCHEDULER) != 0) {
        struct scheduler *def_sched = create_scheduler(CONFIG_DEFAULT_SCHEDULER);
        if(def_sched == NULL) {
            eprintk("Failed to create default scheduler of type \"%s\"\n",
                    CONFIG_DEFAULT_SCHEDULER);
            return 0;
        }
        for(cpu_id_t cpu = 0; cpu < total_num_cpus(); cpu++) {
            int res = assign_cpu_scheduler(def_sched, cpu);
            if(res) {
                eprintk("Failed to assign default scheduler to CPU %ld, (err=%s)\n",
                        (sl_t)cpu, errnostr(res));
                continue;
            }
        }
    }

    return 0;
}
declare_init_desc(smp, init_cpu_scheds, "Initializing CPU Scheduler(s)");

struct thread_state *
query_resched(void)
{
    struct scheduler *sched = current_sched();
    if(sched == NULL) {
        return NULL;
    }
    return scheduler_query_resched(sched);
}

struct thread_state *
force_resched(void)
{
    struct scheduler *sched = current_sched();
    if(sched == NULL) {
        return NULL;
    }
    return scheduler_force_resched(sched);
}

