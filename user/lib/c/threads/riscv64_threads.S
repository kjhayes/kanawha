
.section .text

.align 4

.globl _thrd_start
.type _thrd_start,@function
_thrd_start:
    // exit()!
    li a7, 0
    li a0, -1
    ecall

