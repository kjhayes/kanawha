#ifndef __KANAWHA__ARCH_RISCV64__TRAP_H__
#define __KANAWHA__ARCH_RISCV64__TRAP_H__

#include <arch/riscv64/asm/regs.S>
#include <kanawha/types.h>
#include <kanawha/irq.h>

struct riscv64_excp_state
{

    uint64_t sepc;
    uint64_t stval;
    uint64_t scause;
    uint64_t caller_regs[RISCV64_THREAD_NUM_CALLER_REGS];
    uint64_t callee_regs[RISCV64_THREAD_NUM_CALLEE_REGS];

} __attribute__((packed));

extern struct irq_domain *riscv64_exception_irq_domain;
extern struct irq_domain *riscv64_interrupt_irq_domain;

struct irq_desc *
riscv64_exception_irq_desc(hwirq_t hwirq);

struct irq_desc *
riscv64_interrupt_irq_desc(hwirq_t hwirq);

#endif
