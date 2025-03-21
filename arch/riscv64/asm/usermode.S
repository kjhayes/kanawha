
.section .text

.global __riscv64_enter_usermode
.type __riscv64_enter_usermode, @function
__riscv64_enter_usermode:

    // Set SPIE to 1 (enable interrupts in usermode)
    csrsi sstatus, 5

    // Set SPP to 0 (enter U-Mode)
    csrci sstatus, 8

    // Set our starting address in usermode
    csrw sepc, a0

    // Move our argument into a0
    mv a0, a1

    // Zero out every remaining register
    mv a1, zero
    mv a2, zero
    mv a3, zero
    mv a4, zero
    mv a5, zero
    mv a6, zero
    mv a7, zero
    mv s0, zero
    mv s0, zero
    mv s1, zero
    mv s2, zero
    mv s3, zero
    mv s4, zero
    mv s5, zero
    mv s6, zero
    mv s7, zero
    mv s8, zero
    mv s9, zero
    mv s10, zero
    mv s11, zero
    mv t0, zero
    mv t1, zero
    mv t2, zero
    mv t3, zero
    mv t4, zero
    mv t5, zero
    mv t6, zero
    mv tp, zero
    mv sp, zero
    mv ra, zero
    mv gp, zero

    // Enter User-Mode
    sret

