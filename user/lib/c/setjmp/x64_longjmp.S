
.global _longjmp
.type _longjmp,@function
.global longjmp
.type longjmp,@function

_longjmp:
longjmp:

    // rdi -> pointer to jmp_buf
    // rsi -> integer to return

    movq 0x00(%rdi), %r12
    movq 0x08(%rdi), %r13 
    movq 0x10(%rdi), %r14 
    movq 0x18(%rdi), %r15 
    movq 0x20(%rdi), %rbx 

    movq 0x28(%rdi), %rsp
    movq 0x30(%rdi), %rbp 

    // New return address
    movq 0x38(%rdi), %rdi
    movq %rdi, 0x0(%rsp)

    // Set our return value
    movq %rsi, %rax

    retq

