#ifndef __KANAWHA__ARCH_RISCV64__CPU_H__
#define __KANAWHA__ARCH_RISCV64__CPU_H__

#include <kanawha/types.h>
#include <kanawha/cpu.h>

typedef uint64_t hartid_t;

struct riscv64_cpu
{
    hartid_t hartid;
    struct cpu cpu;
};

#endif
