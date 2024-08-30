#ifndef __KANAWHA__CPU_H__
#define __KANAWHA__CPU_H__

#include <kanawha/device.h>

// CPU ID's must be non-negative and contiguous
typedef int cpu_id_t;

#define NULL_CPU_ID (cpu_id_t)(-1)

struct cpu {
    struct device device;
    cpu_id_t id;

    int is_bsp;

    void *percpu_data;
};

int
bsp_register_smp_cpu(struct cpu *cpu, int is_bsp);

int
unregister_smp_cpu(struct cpu *cpu);

size_t
total_num_cpus(void);

struct cpu *
cpu_from_id(cpu_id_t id);

// Assumes preemption is disabled
cpu_id_t
current_cpu_id(void);

// Should only be used once during initialization (assumes preemption is disabled)
int
set_current_cpu_id(cpu_id_t id);

#endif
