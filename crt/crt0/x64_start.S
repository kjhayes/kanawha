
// 2 MiB Stack
#define STACK_SIZE 0x200000

.text
.code64

.extern __elk_crt__clear_bss
.type __elk_crt__clear_bss,@function

.extern __elk_crt__get_argv
.type __elk_crt__get_argv,@function

.extern __elk_crt__init_stdstreams
.type __elk_crt__init_stdstreams,@function

.extern __elk_crt__init_signal
.type __elk_crt__init_signal,@function

.extern __elk_crt__populate_environ
.type __elk_crt__populate_environ,@function

.global _start
_start: 

// mmap An Anonymous Stack
    movq $7, %rax // mmap
    movq $0, %rdi // NULL_FD
    movq $0, %rsi // file_offset

    // Pass in a pointer to __mmap_where to stash the address of our stack
    movabsq $__mmap_where, %rdx

    movq $STACK_SIZE, %r8 // size
    movq $(0b10), %r9 // MMAP_ANON
    orq $(1ULL<<3), %r9 // MMAP_PROT_READ
    orq $(1ULL<<4), %r9 // MMAP_PROT_WRITE
    syscall

    testq %rax, %rax
    jnz __do_fail_exit

    // set the stack pointer
    movq __mmap_where, %r8
    addq $STACK_SIZE, %r8
    movq %r8, %rsp

    // clear bss 
    callq __elk_crt__clear_bss

    testq %rax, %rax
    jnz __do_fail_exit

    // Map the zero page so no one else will
    callq __elk_crt__map_zero_page

    testq %rax, %rax
    jnz __do_fail_exit

    // Setup stdout, stdin and stderr
    callq __elk_crt__init_stdstreams

    testq %rax, %rax
    jnz __do_fail_exit

    // Setup the default signal handler
    callq __elk_crt__init_signal

    testq %rax, %rax
    jnz __do_fail_exit

    // Setup the environ variable
    callq __elk_crt__populate_environ

    testq %rax, %rax
    jnz __do_fail_exit

    // Setup ARGV
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
    addq $16, %rsp

    // call the main function
    callq main

    // Exit using the value returned from main
    movq %rax, %rdi
    callq exit
    
    // We somehow didn't exit?

__do_fail_exit:
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
    movq $0, %rsi // file_offset

    movabsq $__mmap_where, %rdx // where

    movq $STACK_SIZE, %r8 // size
    movq $(0b10), %r9 // MMAP_ANON
    orq $(1ULL<<3), %r9 // MMAP_PROT_READ
    orq $(1ULL<<4), %r9 // MMAP_PROT_WRITE
    syscall

    testq %rax, %rax
    jnz __thread_start_stack_map_fail 

    // set up the thread stack
    movq __mmap_where, %r8
    addq $STACK_SIZE, %r8
    movq %r8, %rsp

//    subq $8, %rsp

    callq *%rbx

//    addq $8, %rsp

    movq %rax, %rdi
    movq $0, %rax
    syscall

__thread_start_stack_map_fail:
    movq %rax, %rdi // exitcode of mmap
    movq $0, %rax
    syscall

.global __elk_crt__default_signal_handler_entry
.type __elk_crt__default_signal_handler_entry,@function
__elk_crt__default_signal_handler_entry:
    pushq %rax
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    movq %rsp, %rax

    andq $(~0xF), %rsp
    pushq %rax
    callq __elk_crt__default_signal_handler
    popq %rax
    movq %rax, %rsp

    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rax
    
    movq $35, %rax // SIGRET syscall
    syscall

.section .data

__mmap_where:
.quad 0

