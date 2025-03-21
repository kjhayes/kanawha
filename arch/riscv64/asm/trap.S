
#ifndef __ASSEMBLER__
#define __ASSEMBLER__
#endif

#include <arch/riscv64/asm/regs.S>

.extern __percpu_var____current_thread

.global __riscv64_trap_entry
.type __riscv64_trap_entry, @function
.align 2
__riscv64_trap_entry:

    // Swap tp with sscratch
    csrrw tp, sscratch, tp

    // Stash t0 to get a working register
    sd t0, 8(tp)

    // Stash sp
    sd sp, 16(tp)

    // Read sstatus SPP
    csrr t0, sstatus
    andi t0, t0, 1<<8

    bne zero, t0, __riscv64_trap_entry_kernel

__riscv64_trap_entry_user_mode:
    // We came from usermode

    // Get the percpu offset of the current CPU
    ld t0, 0(tp)
    la sp, __percpu_var____current_thread
    add t0, t0, sp

    // t0 is a pointer to a pointer to our current thread
    ld t0, 0(t0)

    // t0 is our current thread
    ld t0, 0(t0)

    // t0 is our current thread's stack pointer
    mv sp, t0

    j __riscv64_trap_entry_common

__riscv64_trap_entry_kernel:
    // We came from the kernel

__riscv64_trap_entry_common:

    // We should be running on the kernel stack now

    // Save our stack
    addi sp, sp, -8
    ld t0, 16(tp)
    sd t0, 0(sp)

    // Restore t0
    ld t0, 8(tp)
    // Restore tp
    csrrw tp, sscratch, tp

    PUSH_CALLEE_REGS();
    PUSH_CALLER_REGS();

    csrr t0, scause
    csrr t1, stval
    csrr t2, sepc
    csrr t3, sstatus
    addi sp, sp, -48
    sd gp, 40(sp)
    sd tp, 32(sp)
    sd t3, 24(sp)
    sd t0, 16(sp)
    sd t1, 8(sp)
    sd t2, 0(sp)

    // Set kernel tp from sscratch
    csrr tp, sscratch

    // struct riscv64_excp_state
    mv a0, sp

    jal riscv64_route_trap

    ld gp, 40(sp)
    ld tp, 32(sp)
    ld t2, 0(sp)
    csrw sepc, t2
    ld t2, 24(sp)
    csrw sstatus, t2
    addi sp, sp, 48

    POP_CALLER_REGS();
    POP_CALLEE_REGS();

    // Restore the stack
    addi sp, sp, 8
    ld sp, -8(sp)

    sret

