
#include <arch/arm64/asm/regs.h>
#include <arch/arm64/excp.h>

.extern arm64_handle_excp
.global arm64_excp_vector_table

.p2align 11
arm64_excp_vector_table:
// EL1 with EL0 stack exceptions
// (We do not use this option, should never happen)
.p2align 7
arm64_excp_el1_el0_stack_sync:
    b .
arm64_excp_el1_el0_stack_sync_end:
.p2align 7
arm64_excp_el1_el0_stack_irq:
    b .
arm64_excp_el1_el0_stack_irq_end:
.p2align 7
arm64_excp_el1_el0_stack_fiq:
    b .
arm64_excp_el1_el0_stack_fiq_end:
.p2align 7
arm64_excp_el1_el0_stack_serror:
    b .
arm64_excp_el1_el0_stack_serror_end:

// EL1 with own stack exceptions
.p2align 7
arm64_excp_el1_sync:
    sub sp, sp, 0x20
    stp x0, x1, [sp, 0x00]
    mov x0, ARM64_EXCP_HWIRQ_SYNC
    mov x1, 0
    stp x0, x1, [sp, 0x10]
    ldp x0, x1, [sp, 0x00]
    add sp, sp, 0x10
    b arm64_excp_common
arm64_excp_el1_sync_end:
.p2align 7
arm64_excp_el1_irq:
    sub sp, sp, 0x20
    stp x0, x1, [sp, 0x00]
    mov x0, ARM64_EXCP_HWIRQ_IRQ
    mov x1, 0
    stp x0, x1, [sp, 0x10]
    ldp x0, x1, [sp, 0x00]
    add sp, sp, 0x10
    b arm64_excp_common
arm64_excp_el1_irq_end:
.p2align 7
arm64_excp_el1_fiq:
    sub sp, sp, 0x20
    stp x0, x1, [sp, 0x00]
    mov x0, ARM64_EXCP_HWIRQ_FIQ
    mov x1, 0
    stp x0, x1, [sp, 0x10]
    ldp x0, x1, [sp, 0x00]
    add sp, sp, 0x10
    b arm64_excp_common
arm64_excp_el1_fiq_end:
.p2align 7
arm64_excp_el1_serror:
    sub sp, sp, 0x20
    stp x0, x1, [sp, 0x00]
    mov x0, ARM64_EXCP_HWIRQ_SERROR
    mov x1, 0
    stp x0, x1, [sp, 0x10]
    ldp x0, x1, [sp, 0x00]
    add sp, sp, 0x10
    b arm64_excp_common
arm64_excp_el1_serror_end:

// EL0 64-bit exceptions
.p2align 7
arm64_excp_el0_64_sync:
    b .
arm64_excp_el0_64_sync_end:
.p2align 7
arm64_excp_el0_64_irq:
    b .
arm64_excp_el0_64_irq_end:
.p2align 7
arm64_excp_el0_64_fiq:
    b .
arm64_excp_el0_64_fiq_end:
.p2align 7
arm64_excp_el0_64_serror:
    b .
arm64_excp_el0_64_serror_end:

// EL0 32-bit exceptions
.p2align 7
arm64_excp_el0_32_sync:
    b .
arm64_excp_el0_32_sync_end:
.p2align 7
arm64_excp_el0_32_irq:
    b .
arm64_excp_el0_32_irq_end:
.p2align 7
arm64_excp_el0_32_fiq:
    b .
arm64_excp_el0_32_fiq_end:
.p2align 7
arm64_excp_el0_32_serror:
    b .
arm64_excp_el0_32_serror_end:

.global arm64_excp_common
.type arm64_excp_common,@function
arm64_excp_common:
    // 0x10 worth of flags currently pushed on the stack,
    // which we need to clean up at the end
    PUSH_CALLER_REGS();
    PUSH_CALLEE_REGS();
    sub sp, sp, 0x20
    mrs x0, SPSR_EL1
    mrs x1, ELR_EL1
    mrs x2, ESR_EL1
    mrs x3, FAR_EL1
    stp x0, x1, [sp, 0x00]
    stp x2, x3, [sp, 0x10]
    mov x0, sp
    bl arm64_handle_excp
    ldp x0, x1, [sp, 0x00]
    msr SPSR_EL1, x0
    msr ELR_EL1, x1
    add sp, sp, 0x20
    POP_CALLEE_REGS();
    POP_CALLER_REGS();
    add sp, sp, 0x10
    eret

