#ifndef __KANAWHA__CPU_H__
#define __KANAWHA__CPU_H__

#include <kanawha/registry.h>
#include <kanawha/stddef.h>

// CPU ID's must be non-negative and contiguous
typedef int cpu_id_t;

#define NULL_CPU_ID (cpu_id_t)(-1)

#define CPU_FLAG_IS_BSP (1UL << 0)

struct cpu
{
    cpu_id_t id;

    unsigned long flags;

    struct registry_node registry_node;

    void *percpu_data;
};

size_t
total_num_cpus(void);

struct cpu *
cpu_from_id(cpu_id_t id);

// Assumes preemption is disabled
cpu_id_t
current_cpu_id(void);

// Assumes preemption is disabled
static inline struct cpu *
current_cpu(void)
{
    return cpu_from_id(current_cpu_id());
}

// Should only be used once during initialization
// (assumes preemption is disabled)
int
set_current_cpu_id(cpu_id_t id);

DECLARE_REGISTRY(cpu);

// >= 0 -> runtime percentage of this CPU's idle thread
// < 0 -> errno value
ssize_t
cpu_idle_percentage(cpu_id_t id);

#endif
