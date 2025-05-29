
#include <kanawha/cpu.h>
#include <kanawha/spinlock.h>
#include <kanawha/string.h>
#include <kanawha/printk.h>
#include <kanawha/stddef.h>
#include <kanawha/percpu.h>
#include <kanawha/lock.h>

static struct cpu * system_cpus[CONFIG_MAX_CPUS] = { 0 };
static size_t __num_cpus = 0;

DEFINE_LOCAL_THREAD_LOCK(system_cpus_lock);

int
bsp_register_smp_cpu(struct cpu *cpu, int is_bsp)
{
    system_cpus_lock_acquire();
    int found = 0;

    if(is_bsp) {
        if(system_cpus[0] != NULL) {
            panic("Tried to register multiple BSP(s)!\n");
        }
        found = 1;
        system_cpus[0] = cpu;
        cpu->id = 0;
        cpu->is_bsp = 1;
    }
    else {
        for(cpu_id_t id = 1; id < CONFIG_MAX_CPUS; id++) {
            if(system_cpus[id] == NULL) {
                found = 1;
                system_cpus[id] = cpu;
                cpu->id = id;
                cpu->is_bsp = 0;
                break;
            }
        }
    }

    if(!found) {
        eprintk("Tried to register too many CPU(s)! (Try increasing the value of CONFIG_MAX_CPUS)\n");
        system_cpus_lock_release();
        return -ENOMEM;
    }
    __num_cpus++;
    system_cpus_lock_release();


    int res = init_cpu_percpu_data(cpu);
    if(res) {
        eprintk("Failed to setup percpu data for CPU %ld\n", cpu->id);
        return res;
    }

    return 0;
}

int
unregister_smp_cpu(struct cpu *cpu)
{
    system_cpus_lock_acquire();
    system_cpus[cpu->id] = NULL;
    __num_cpus--;
    system_cpus_lock_acquire();
    return 0;
}

size_t
total_num_cpus(void) {
    return __num_cpus;
}

struct cpu *
cpu_from_id(cpu_id_t id) {
    if(id < 0 || id >= CONFIG_MAX_CPUS) {
        return NULL;
    }
    return system_cpus[id];
}

DECLARE_STATIC_PERCPU_VAR(cpu_id_t, __current_cpu_id);

cpu_id_t
current_cpu_id(void) {
    return *(cpu_id_t*)percpu_ptr(percpu_addr(__current_cpu_id));
}

int
set_current_cpu_id(cpu_id_t id)
{
    *(cpu_id_t*)percpu_ptr(percpu_addr(__current_cpu_id)) = id;
    return 0;
}

