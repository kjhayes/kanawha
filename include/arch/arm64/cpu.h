#ifndef __KANAWHA__ARM64_CPU_H__
#define __KANAWHA__ARM64_CPU_H__

#include <kanawha/cpu.h>
#include <kanawha/percpu.h>
#include <arch/arm64/sysreg.h>

typedef uint64_t mpid_t;

struct arm64_cpu {
    struct cpu cpu;
    char *name;
};

DECLARE_EXTERN_PERCPU_VAR(mpid_t, arm64_mpid);

static inline int
provide_mpid(mpid_t mpid, cpu_id_t cpu)
{
    mpid_t *ptr = percpu_ptr_specific(percpu_addr(arm64_mpid), cpu);
    *ptr = mpid;
    printk("Setting CPU(%ld) MPID to 0x%lx\n", (sl_t)cpu, (ul_t)mpid);
    return 0;
}

static inline mpid_t
cpu_id_to_mpid(cpu_id_t cpu)
{
    mpid_t *id = percpu_ptr_specific(percpu_addr(arm64_mpid), cpu);
    return *id;
}

static inline int
provide_bsp_mpid(mpid_t mpid)
{
    return provide_mpid(mpid, 0);
}

static inline mpid_t
current_mpid_from_mpidr(void)
{
    uint64_t mpidr = arm64_sysreg_readq(MPIDR_EL1);
    mpidr &= ~(1UL<<31); // Clear RES1 bit
    mpidr &= ~(1UL<<30); // Clear "uniprocessor" bit
    return (mpid_t)mpidr;
}

static inline mpid_t
current_mpid(void)
{
    mpid_t *ptr = percpu_ptr(percpu_addr(arm64_mpid));
    return *ptr;
}

#endif
