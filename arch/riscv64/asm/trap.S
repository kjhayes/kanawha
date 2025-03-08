
#ifndef __ASSEMBLER__
#define __ASSEMBLER__
#endif

#include <arch/riscv64/asm/regs.S>

.global __riscv64_trap_entry
.type __riscv64_trap_entry, @function
.align 2
__riscv64_trap_entry:
    PUSH_CALLEE_REGS();
    PUSH_CALLER_REGS();

    csrr t0, scause
    csrr t1, stval
    csrr t2, sepc
    addi sp, sp, -24
    sd t0, 16(sp)
    sd t1, 8(sp)
    sd t2, 0(sp)

    // struct riscv64_excp_state
    mv a0, sp

    jal riscv64_route_trap

    ld t2, 0(sp)
    csrw sepc, t2
    addi sp, sp, 24

    POP_CALLER_REGS();
    POP_CALLEE_REGS();
    sret

