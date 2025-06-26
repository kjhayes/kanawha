
.global __arch_longjmp
.type __arch_longjmp,@function
__arch_longjmp:

    // rdi -> pointer to jmp_buf
    // rsi -> integer to return

    // Restore the old %rsp
    movq 0(%rdi), %rsp

    // Overwrite our return address
    movq 16(%rdi), %rbp
    movq %rbp, 0(%rsp)

    // Restore the old %rbp
    movq 8(%rdi), %rbp

    // Set our return value
    movq %rsi, %rax

    retq

