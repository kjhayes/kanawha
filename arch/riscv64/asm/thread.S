
#include <arch/riscv64/asm/regs.S>

.global __riscv64_thread_entry
.type __riscv64_thread_entry, @function
__riscv64_thread_entry:
    // a0: void *in
    // a1: void(*func)(void *in)

    jalr a1

    j .

.global __riscv64_thread_run_threadless
.type __riscv64_thread_run_threadless, @function
__riscv64_thread_run_threadless:
    // a0 -> in
    // a1 -> func
    // a2 -> sp_ptr
    PUSH_CALLER_REGS()
    PUSH_CALLEE_REGS()

    addi sp, sp, -16
    csrr s0, sstatus
    csrr s1, sepc
    sd s0, 0(sp)
    sd s1, 8(sp)

    // Save the stack
    sd sp, 0(a2)

    // a0 is already our argument
    // DO NOT OVERWRITE RA
    jr a1

    // We should never return
    j .

.global __riscv64_thread_run_thread
.type __riscv64_thread_run_thread, @function
__riscv64_thread_run_thread:
    mv sp, a0 // Retore the stack

    ld s0, 0(sp) // sstatus
    ld s1, 8(sp) // sepc
    csrw sstatus, s0
    csrw sepc, s1
    addi sp, sp, 16

    POP_CALLEE_REGS()
    POP_CALLER_REGS()
    ret

