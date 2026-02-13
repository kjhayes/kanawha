
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

.global __elk_crt__signal_handler_entry
.type __elk_crt__signal_handler_entry,@function
__elk_crt__signal_handler_entry:
  
    // Save flags before we do a subtraction (we will need to swap this later)
    pushfq
    subq $8, %rsp

    subq $64, %rsp
    movq %rdi,  0(%rsp)
    movq %rsi,  8(%rsp)
    movq %rdx, 16(%rsp) 
    movq %rcx, 24(%rsp)
    movq %r8,  32(%rsp)
    movq %r9,  40(%rsp)
    movq %r10, 48(%rsp)
    movq %r11, 56(%rsp)

    // "swap" the saved flags and return address allocation
    movq 72(%rsp), %rdi
    movq %rdi, 64(%rsp)

    movq %rsp, %rdi
    andq $(~0xF), %rsp

    subq $16, %rsp
    movq %rdi, 0(%rsp)

    addq $72, %rdi // Get a pointer to our return address on the stack


    callq __elk_crt__handle_signal

    movq 0(%rsp), %rdi

    movq %rdi, %rsp

    movq  0(%rsp), %rdi
    movq  8(%rsp), %rsi
    movq 16(%rsp), %rdx
    movq 24(%rsp), %rcx
    movq 32(%rsp), %r8
    movq 40(%rsp), %r9
    movq 48(%rsp), %r10
    movq 56(%rsp), %r11
    addq $64, %rsp

    popfq

    retq

.section .data

__mmap_where:
.quad 0

