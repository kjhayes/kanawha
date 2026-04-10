
.globl _thrd_start
_thrd_start:
    // exit()!
    li a7, 0
    li a0, -1
    ecall

