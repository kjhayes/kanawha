
#ifndef __ASSEMBLER__
#define __ASSEMBLER__
#endif
#include <setjmp.h>

.global setjmp
.type setjmp,@function
setjmp:
    // rdi -> pointer to jmp_buf of length __JMP_BUFSIZE

    movq %rsp, 0(%rdi)
    movq %rbp, 8(%rdi)
    movq 0(%rsp), %rbp
    movq %rbp, 16(%rdi)

    // restore rbp
    movq 8(%rdi), %rbp

    movq $0, %rax

    retq

