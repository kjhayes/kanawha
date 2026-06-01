#ifndef __KANAWHA__ARM64_EXCP_H__
#define __KANAWHA__ARM64_EXCP_H__

#define ARM64_EXCP_HWIRQ_SYNC   (0)
#define ARM64_EXCP_HWIRQ_IRQ    (1)
#define ARM64_EXCP_HWIRQ_FIQ    (2)
#define ARM64_EXCP_HWIRQ_SERROR (3)

#define ARM64_EXCP_FLAG_USER  (1UL<<0)
#define ARM64_EXCP_FLAG_32BIT (1UL<<1)

#ifndef __ASSEMBLER__
#include <arch/arm64/asm/regs.h>
#include <kanawha/attribute.h>
#include <kanawha/types.h>
#include <kanawha/irq_domain.h>

struct __packed arm64_excp_state {
    uint64_t spsr;
    uint64_t elr;
    uint64_t esr;
    uint64_t far;
    uint64_t callee_regs[ARM64_THREAD_CALLEE_PUSH_SIZE/8];
    uint64_t caller_regs[ARM64_THREAD_CALLER_PUSH_SIZE/8];
    uint64_t hwirq;
    uint64_t flags;
};

irq_t arm64_exception_irq(hwirq_t hwirq);

#endif
#endif
