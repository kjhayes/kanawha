
.section .text

#define STACK_SIZE 0x10000

.align 4

.globl _thrd_start
.type _thrd_start,@function
_thrd_start:
    mv s0, a0 // Stash thread creation state

    // Load gp
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    // Map a stack
    li a7, 7 // mmap syscall
    li a0, 0 // NULL_FD
    li a1, 0 // file_offset

    // Pointer to stash the new stack location
    add a2, s0, 16

    li a3, STACK_SIZE
    li a4, (0b10 | (1<<3) | (1<<4))

    ecall

    bne zero, a0, __do_fail_exit

    ld sp, 16(s0)
    li t0, STACK_SIZE
    add sp, sp, t0

    ld a0, 8(s0)
    ld s1, 0(s0)

    // Mark us as inited (s0 is now invalid)
    li t0, 1
    sb t0, 24(s0)

    jalr ra, s1

    // Exit
    li a7, 0
    ecall

__do_fail_exit:
    // Exit
    li a7, 0
    ecall

