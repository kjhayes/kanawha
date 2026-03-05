#ifndef __KANAWHA__ARCH_RISCV64__CPU_H__
#define __KANAWHA__ARCH_RISCV64__CPU_H__

#include <kanawha/cpu.h>
#include <kanawha/percpu.h>
#include <kanawha/types.h>

typedef uint64_t hartid_t;

struct riscv64_cpu
{
    struct cpu cpu;
};

DECLARE_EXTERN_PERCPU_VAR(hartid_t, riscv64_hartid);
DECLARE_EXTERN_PERCPU_VAR(freq_t, riscv64_timebase_freq);

static inline int
provide_hartid(hartid_t hartid, cpu_id_t cpu)
{
    hartid_t *ptr = percpu_ptr_specific(percpu_addr(riscv64_hartid), cpu);
    *ptr = hartid;
    return 0;
}

static inline int
provide_bsp_hartid(hartid_t hartid)
{
    return provide_hartid(hartid, 0);
}

static inline hartid_t
current_hartid(void)
{
    hartid_t *id = percpu_ptr(percpu_addr(riscv64_hartid));
    return *id;
}

static inline hartid_t
cpu_id_to_hartid(cpu_id_t cpu)
{
    hartid_t *id = percpu_ptr_specific(percpu_addr(riscv64_hartid), cpu);
    return *id;
}

static inline freq_t
riscv64_cpu_timebase(cpu_id_t cpu)
{
    freq_t *freq = percpu_ptr_specific(percpu_addr(riscv64_timebase_freq), cpu);
    return *freq;
}

#endif
