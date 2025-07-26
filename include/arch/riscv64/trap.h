#ifndef __KANAWHA__ARCH_RISCV64__TRAP_H__
#define __KANAWHA__ARCH_RISCV64__TRAP_H__

#include <arch/riscv64/asm/regs.S>
#include <kanawha/types.h>
#include <kanawha/irq.h>
#include <kanawha/attribute.h>

#define RISCV64_EXCEPTION_XLIST(X)\
X(0, "Instruction Address Misaligned")\
X(1, "Instruction Access Fault")\
X(2, "Illegal Instruction")\
X(3, "Breakpoint")\
X(4, "Load Address Misaligned")\
X(5, "Load Access Fault")\
X(6, "Store/AMO Address Misaligned")\
X(7, "Store/AMO Access Fault")\
X(8, "Environment Call From U-Mode")\
X(9, "Environment Call From S-Mode")\
X(12, "Instruction Page Fault")\
X(13, "Load Page Fault")\
X(15, "Store/AMO Page Fault")

#define RISCV64_INTERRUPT_XLIST(X)\
X(1, "Supervisor Software Interrupt")\
X(5, "Supervisor Timer Interrupt")\
X(9, "Supervisor External Interrupt")\

#define RISCV64_EXCEPTION_IRQ_DOMAIN_SIZE 64
#define RISCV64_INTERRUPT_IRQ_DOMAIN_SIZE 64

struct __packed riscv64_excp_state
{
    uint64_t sepc;
    uint64_t stval;
    uint64_t scause;
    uint64_t sstatus;
    uint64_t tp;
    uint64_t gp;
    uint64_t caller_regs[RISCV64_THREAD_NUM_CALLER_REGS];
    uint64_t callee_regs[RISCV64_THREAD_NUM_CALLEE_REGS];

};

extern struct irq_domain *riscv64_exception_irq_domain;
extern struct irq_domain *riscv64_interrupt_irq_domain;

struct irq_desc *
riscv64_exception_irq_desc(hwirq_t hwirq);

struct irq_desc *
riscv64_interrupt_irq_desc(hwirq_t hwirq);

struct irq_domain *
riscv64_shared_interrupt_domain(void);
struct irq_domain *
riscv64_shared_exception_domain(void);

#endif
