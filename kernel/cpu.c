
#include <kanawha/cpu.h>
#include <kanawha/spinlock.h>
#include <kanawha/string.h>
#include <kanawha/printk.h>
#include <kanawha/stddef.h>
#include <kanawha/percpu.h>

static DECLARE_SPINLOCK(system_cpus_lock);
static struct cpu * system_cpus[CONFIG_MAX_CPUS] = { 0 };
static size_t __num_cpus = 0;

static int
smp_cpu_read_name(
        struct device *dev,
        char *buf,
        size_t size)
{
    struct cpu *cpu = container_of(dev, struct cpu, device);
    snprintk(buf, size, "cpu%d", cpu->id);
    return 0;
}

static struct device_ops
smp_cpu_ops = {
    .read_name = smp_cpu_read_name,
};

int
bsp_register_smp_cpu(struct cpu *cpu, int is_bsp)
{
    spin_lock(&system_cpus_lock);
    int found = 0;

    if(is_bsp) {
        if(system_cpus[0] != NULL) {
            panic("Tried to register multiple BSP(s)!\n");
        }
        found = 1;
        system_cpus[0] = cpu;
        cpu->id = 0;
        cpu->is_bsp = 1;

        int res = register_device(
                &cpu->device,
                &smp_cpu_ops,
                NULL);
        if(res) {
            panic("Failed to register BSP CPU device!\n");
        }
    }
    else {
        for(cpu_id_t id = 1; id < CONFIG_MAX_CPUS; id++) {
            if(system_cpus[id] == NULL) {
                found = 1;
                system_cpus[id] = cpu;
                cpu->id = id;
                cpu->is_bsp = 0;

                int res = register_device(
                        &cpu->device,
                        &smp_cpu_ops,
                        NULL);
                if(res) {
                    eprintk("Failed to register AP CPU device!\n");
                    spin_unlock(&system_cpus_lock);
                    return res;
                }
                break;
            }
        }
    }

    if(!found) {
        eprintk("Tried to register too many CPU(s)! (Try increasing the value of CONFIG_MAX_CPUS)\n");
        spin_unlock(&system_cpus_lock);
        return -ENOMEM;
    }
    __num_cpus++;
    spin_unlock(&system_cpus_lock);


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
    spin_lock(&system_cpus_lock);
    int res = unregister_device(&cpu->device);
    if(res) {
        spin_unlock(&system_cpus_lock);
        return res;
    }
    system_cpus[cpu->id] = NULL;
    __num_cpus--;
    spin_unlock(&system_cpus_lock);
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

