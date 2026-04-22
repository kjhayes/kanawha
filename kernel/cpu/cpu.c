
#include <kanawha/cpu.h>
#include <kanawha/lock.h>
#include <kanawha/percpu.h>
#include <kanawha/printk.h>
#include <kanawha/registry.h>
#include <kanawha/spinlock.h>
#include <kanawha/stddef.h>
#include <kanawha/string.h>
#include <kanawha/thread.h>

DEFINE_LOCAL_THREAD_LOCK(system_cpus_lock);
static struct cpu *system_cpus[CONFIG_MAX_CPUS] = {0};
static size_t __num_cpus = 0;

size_t
total_num_cpus(void)
{
    return __num_cpus;
}

struct cpu *
cpu_from_id(cpu_id_t id)
{
    if(id < 0 || id >= CONFIG_MAX_CPUS)
    {
        return NULL;
    }
    return system_cpus[id];
}

DECLARE_STATIC_PERCPU_VAR(cpu_id_t, __current_cpu_id);

cpu_id_t
current_cpu_id(void)
{
    return *(cpu_id_t *)percpu_ptr(percpu_addr(__current_cpu_id));
}

int
set_current_cpu_id(cpu_id_t id)
{
    *(cpu_id_t *)percpu_ptr(percpu_addr(__current_cpu_id)) = id;
    return 0;
}

static int
cpu_on_register(struct cpu *cpu)
{
    system_cpus_lock_acquire();
    int found = 0;

    if(cpu->flags & CPU_FLAG_IS_BSP)
    {
        if(system_cpus[0] != NULL)
        {
            panic("Tried to register multiple BSP(s)!\n");
        }
        found = 1;
        system_cpus[0] = cpu;
        cpu->id = 0;
    }
    else
    {
        for(cpu_id_t id = 1; id < CONFIG_MAX_CPUS; id++)
        {
            if(system_cpus[id] == NULL)
            {
                found = 1;
                system_cpus[id] = cpu;
                cpu->id = id;
                cpu->flags = 0;
                break;
            }
        }
    }

    if(!found)
    {
        eprintk("Tried to register too many CPU(s)! (Try increasing the value "
                "of CONFIG_MAX_CPUS)\n");
        system_cpus_lock_release();
        return -ENOMEM;
    }
    __num_cpus++;
    system_cpus_lock_release();

    int res = init_cpu_percpu_data(cpu);
    if(res)
    {
        eprintk("Failed to setup percpu data for CPU %ld\n", cpu->id);
        system_cpus_lock_acquire();
        system_cpus[cpu->id] = NULL;
        __num_cpus--;
        system_cpus_lock_acquire();
        return res;
    }

    return 0;
}

static int
cpu_on_unregister(struct cpu *cpu)
{
    system_cpus_lock_acquire();
    system_cpus[cpu->id] = NULL;
    __num_cpus--;
    system_cpus_lock_acquire();
    return 0;
}

DEFINE_REGISTRY(cpu, registry_node, cpu_on_register, cpu_on_unregister)

ssize_t
cpu_idle_percentage(cpu_id_t cpu)
{
    struct thread_state *idle = cpu_idle_thread(cpu);
    if(idle == NULL)
    {
        printk("cpu_idle_percentage: failed to get CPU(%ld) idle thread!\n",
               (sl_t)cpu);
        return -EINVAL;
    }
    return thread_running_percentage(idle);
}
