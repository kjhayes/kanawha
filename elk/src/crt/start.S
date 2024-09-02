
// 8 MiB Stack
#define STACK_TOP 0x1000000
#define STACK_SIZE 0x1000000
#define STACK_BASE (STACK_TOP + STACK_SIZE)

.extern __elk_crt__get_argv
.type __elk_crt__get_argv,@function

.global _start
_start: 

// mmap An Anonymous Stack
    movq $5, %rax // mmap
    movq $0, %rdi // NULL_FD
    movq $0, %rdi // file_offset
    movq $STACK_TOP, %rdx // where
    movq $STACK_SIZE, %r8 // size
    movq $(0b11), %r9 // MMAP_PROT_READ|MMAP_PROT_WRITE
    movq $(0b10), %r10 // MMAP_ANON
    syscall

    testq %rax, %rax
    jnz __stack_map_fail

    movq $STACK_BASE, %rsp

    subq $16, %rsp

    // argc ptr
    leaq 0(%rsp), %rdi
    // argv ptr
    leaq 8(%rsp), %rsi
    
    callq __elk_crt__get_argv

    // argc
    movq 0(%rsp), %rdi
    // argv
    movq 8(%rsp), %rsi

    // align the stack
    subq $8, %rsp

    // call the main function
    callq main

    addq $8, %rsp

    // Exit using the value returned from main
    movq %rax, %rdi
    movq $0, %rax
    syscall
    jmp . // safety loop

__stack_map_fail:
    movq $0, %rax // exit
    movq $55, %rdi // exitcode 55
    syscall
    jmp . // safety loop

