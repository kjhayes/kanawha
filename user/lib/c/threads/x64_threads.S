
#define STACK_SIZE (0x100000)

.globl _thrd_start
_thrd_start:

    // Stash the thread creation state.
    movq %rdi, %rbx

    // mmap An Anonymous Stack
    movq $7, %rax // mmap
    movq $0, %rdi // NULL_FD
    movq $0, %rsi // file_offset

    leaq 16(%rbx), %rdx // where

    movq $STACK_SIZE, %r8 // size
    movq $(0b10), %r9 // MMAP_ANON
    orq $(1ULL<<3), %r9 // MMAP_PROT_READ
    orq $(1ULL<<4), %r9 // MMAP_PROT_WRITE
    syscall

    movq 16(%rbx), %rsp
    addq $STACK_SIZE, %rsp

    // read the rest of our creation info
    movq 8(%rbx), %r8 // state
    movq 0(%rbx), %r9 // func

    mfence
    movb $1, 24(%rbx) // notify we have been inited (%rbx is an invalid pointer after this)

    // call the actual thread function
    movq %r8, %rdi
    callq *%r9

    movq %rax, %rdi
    callq thrd_exit

_thrd_error_loop:
    // something has gone wrong...
    jmp _thrd_error_loop

