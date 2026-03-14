
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/lock.h>
#include <kanawha/percpu.h>
#include <kanawha/scheduler.h>
#include <kanawha/stddef.h>
#include <kanawha/stree.h>
#include <kanawha/string.h>

static DECLARE_STREE(sched_type_tree);
DEFINE_LOCAL_THREAD_LOCK(sched_type_tree_lock);

static DECLARE_ILIST(sched_instance_list);
DEFINE_LOCAL_THREAD_LOCK(sched_instance_list_lock);

DECLARE_STATIC_PERCPU_VAR(struct scheduler *, current_scheduler);

int
register_scheduler_type(struct scheduler_type *type)
{
    printk("Registering Scheduler Type: \"%s\"\n", type->name);

    sched_type_tree_lock_acquire();
    struct stree_node *node = stree_get(&sched_type_tree, type->name);
    if(node != NULL)
    {
        sched_type_tree_lock_release();
        eprintk("Scheduler with name \"%s\" has already been registered!\n");
        return -EEXIST;
    }

    type->tree_node.key = type->name;
    stree_insert(&sched_type_tree, &type->tree_node);

    ilist_init(&type->instance_list);

    sched_type_tree_lock_release();

    return 0;
}

struct scheduler *
create_scheduler(const char *type_name, const char *sched_name)
{
    struct scheduler_type *type;
    sched_type_tree_lock_acquire();
    struct stree_node *type_node = stree_get(&sched_type_tree, type_name);
    if(type_node == NULL)
    {
        sched_type_tree_lock_release();
        return NULL;
    }
    type = container_of(type_node, struct scheduler_type, tree_node);
    sched_type_tree_lock_release();

    struct scheduler *sched = scheduler_type_alloc_instance(type);
    if(sched == NULL)
    {
        return sched;
    }

    sched->num_cpus = 0;
    sched->type = type;
    sched->name = kstrdup(sched_name);
    if(sched->name == NULL)
    {
        scheduler_type_free_instance(type, sched);
    }
    spinlock_init(&sched->lock);

    sched_instance_list_lock_acquire();
    ilist_push_tail(&sched_instance_list, &sched->instance_list_node);
    sched_instance_list_lock_release();

    return sched;
}

int
assign_cpu_scheduler(struct scheduler *sched, cpu_id_t cpu)
{
    struct scheduler *existing = *(struct scheduler **)percpu_ptr_specific(
        percpu_addr(current_scheduler),
        cpu);
    if(existing == sched)
    {
        return 0;
    }

    if(existing != NULL)
    {
        // The locking here is questionable
        int flags = spin_lock_pair_irq_save(&existing->lock, &sched->lock);
        existing->num_cpus--;
        sched->num_cpus++;
        (*(struct scheduler **)
             percpu_ptr_specific(percpu_addr(current_scheduler), cpu)) = sched;
        spin_unlock_pair_irq_restore(&existing->lock, &sched->lock, flags);
    }
    else
    {
        int flags = spin_lock_irq_save(&sched->lock);
        sched->num_cpus++;
        (*(struct scheduler **)
             percpu_ptr_specific(percpu_addr(current_scheduler), cpu)) = sched;
        spin_unlock_irq_restore(&sched->lock, flags);
    }

    return 0;
}

struct scheduler *
current_sched(void)
{
    struct scheduler **current_sched_ptr =
        percpu_ptr(percpu_addr(current_scheduler));

    DEBUG_ASSERT(KERNEL_ADDR(current_sched_ptr));

    return *current_sched_ptr;
}

static int
init_cpu_scheds(void)
{
    // Clear every CPU(s) scheduler to a NULL value
    for(cpu_id_t cpu = 0; cpu < total_num_cpus(); cpu++)
    {
        *(struct scheduler **)percpu_ptr_specific(
            percpu_addr(current_scheduler),
            cpu) = NULL;
    }

    // If we have a default scheduler, create an instance, and assign it to
    // every CPU
    if(strlen(CONFIG_DEFAULT_SCHEDULER) != 0)
    {
        struct scheduler *def_sched =
            create_scheduler(CONFIG_DEFAULT_SCHEDULER, "default");
        if(def_sched == NULL)
        {
            eprintk("Failed to create default scheduler of type \"%s\"\n",
                    CONFIG_DEFAULT_SCHEDULER);
            return -EINVAL;
        }
        for(cpu_id_t cpu = 0; cpu < total_num_cpus(); cpu++)
        {
            int res = assign_cpu_scheduler(def_sched, cpu);
            if(res)
            {
                eprintk("Failed to assign default scheduler to "
                        "CPU %ld, (err=%s)\n",
                        (sl_t)cpu,
                        errnostr(res));
                continue;
            }
        }
    }

    return 0;
}
declare_init_desc(smp, init_cpu_scheds, "Initializing CPU Scheduler(s)");

int
soft_resched(void)
{
    if(current_thread_is_rescheduled())
    {
        return 0;
    }

    struct scheduler *sched = current_sched();
    if(sched == NULL)
    {
        // Can't reschedule without a scheduler
        return 0;
    }
    scheduler_soft_resched(sched);
    return 0;
}

int
hard_resched(void)
{
    int res;

    if(current_thread_is_rescheduled())
    {
        return 0;
    }

    struct thread_state *idle;
    struct scheduler *sched = current_sched();
    if(sched == NULL)
    {
        // If we have no scheduler switch to
        // the idle thread...
        goto idle_exit;
    }
    else
    {

        res = scheduler_hard_resched(sched);
        if(res)
        {
            goto idle_exit;
        }
        return 0;
    }

idle_exit:
    idle = idle_thread();
    DEBUG_ASSERT(KERNEL_ADDR(idle));
    thread_schedule(idle);
    return 0;
}

// Default Implementations
int
sched_debug_dump_no_info(struct scheduler *sched, printk_f *printer)
{
    // Just don't print anything
    return 0;
}

// Debug Printing

void
dump_schedulers(printk_f *printer)
{
    sched_instance_list_lock_acquire();
    ilist_node_t *node;
    (*printer)("--- Scheduler Instances ---\n");
    ilist_for_each(node, &sched_instance_list)
    {
        struct scheduler *sched =
            container_of(node, struct scheduler, instance_list_node);
        (*printer)("\tSCHED(%s) type=\"%s\" num_cpus=%ld\n",
                   sched->name == NULL ? "UNNAMED" : sched->name,
                   sched->type->name,
                   (sl_t)sched->num_cpus);
        scheduler_debug_dump(sched, printer);
    }
    sched_instance_list_lock_release();
}
