
// 8 MiB Stack
#define STACK_TOP 0x1000000
#define STACK_SIZE 0x1000000

.text
.code64

.extern __elk_crt__get_argv
.type __elk_crt__get_argv,@function

.global _start
_start: 

// mmap An Anonymous Stack
    movq $7, %rax // mmap
    movq $0, %rdi // NULL_FD
    movq $0, %rdi // file_offset

    movq __num_stacks, %rcx
    imulq $STACK_SIZE, %rcx, %rdx
    addq $STACK_TOP, %rdx // where

    movq %rdx, %rsp
    addq $STACK_SIZE, %rsp

    movq $STACK_SIZE, %r8 // size
    movq $(0b11), %r9 // MMAP_PROT_READ|MMAP_PROT_WRITE
    movq $(0b10), %r10 // MMAP_ANON
    syscall

    testq %rax, %rax
    jnz __stack_map_fail
 
    movq __num_stacks, %rcx
    addq $1, %rcx
    movq %rcx, __num_stacks

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

__stack_map_fail:
    movq %rax, %rdi // exitcode of mmap
    movq $0, %rax // exit
    syscall

.global _thread_start
_thread_start:

    // Stash our argument (thread func)
    movq %rdi, %rbx

    // mmap An Anonymous Stack
    movq $7, %rax // mmap
    movq $0, %rdi // NULL_FD
    movq $0, %rdi // file_offset

    // Grab the stack lock
__thread_start_stack_spin_lock:
    movq $1, %rcx
    lock xchg __stack_lock, %rcx
    testq %rcx, %rcx
    jnz __thread_start_stack_spin_lock

    movq __num_stacks, %rcx
    imulq $STACK_SIZE, %rcx, %rdx
    addq $STACK_TOP, %rdx // where
    
    movq %rdx, %rsp
    addq $STACK_SIZE, %rsp

    movq $STACK_SIZE, %r8 // size
    movq $(0b11), %r9 // MMAP_PROT_READ|MMAP_PROT_WRITE
    movq $(0b10), %r10 // MMAP_ANON
    syscall

    testq %rax, %rax
    jnz __thread_start_stack_map_fail 

    movq __num_stacks, %rcx
    addq $1, %rcx
    movq %rcx, __num_stacks

    movq $0, __stack_lock
    
    subq $8, %rsp

    callq *%rbx

    addq $8, %rsp

    movq %rax, %rdi
    movq $0, %rax
    syscall

__thread_start_stack_map_fail:
    movq $0, __stack_lock
    movq %rax, %rdi // exitcode of mmap
    movq $0, %rax
    syscall

.data

__stack_lock:
.quad 0
__num_stacks:
.quad 0

