
#ifndef __ASSEMBLER__
#define __ASSEMBLER__
#endif
#include <setjmp.h>

.global sigsetjmp
.type sigsetjmp,@function
sigsetjmp: // TODO
   jmp .

.global _setjmp
.type _setjmp,@function
.global setjmp
.type setjmp,@function
_setjmp:
setjmp:
    // rdi -> pointer to jmp_buf of length __JMP_BUFSIZE

    // Save all "callee" saved registers
    movq %r12, 0x00(%rdi)
    movq %r13, 0x08(%rdi)
    movq %r14, 0x10(%rdi)
    movq %r15, 0x18(%rdi)
    movq %rbx, 0x20(%rdi)

    // Save the stack frame
    movq %rsp, 0x28(%rdi)
    movq %rbp, 0x30(%rdi)

    // Save our current return address
    movq 0x0(%rsp), %rsi
    movq %rsi, 0x38(%rdi)

    // Return 0
    xorq %rax, %rax
    retq

