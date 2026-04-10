
.extern __global_pointer$

.text

#define STACK_SIZE 0x200000

.global _thread_start
_thread_start:
    mv s0, a0 // Stash function pointer

    // Load gp
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    // Map a stack
    li a7, 7 // mmap syscall
    li a0, 0 // NULL_FD
    li a1, 0 // file_offset

    // Pointer to stash the new stack location
    la a2, __mmap_where

    li a3, STACK_SIZE
    li a4, (0b10 | (1<<3) | (1<<4))

    ecall

    bne zero, a0, __do_fail_exit

    ld sp, __mmap_where
    li t0, STACK_SIZE
    add sp, sp, t0

    jalr ra, s0 

    // Exit
    li a7, 0
    ecall

    j .

.global _start
_start:

    // Load gp
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    // Map a stack
    li a7, 7 // mmap syscall
    li a0, 0 // NULL_FD
    li a1, 0 // file_offset

    // Pointer to stash the new stack location
    la a2, __mmap_where

    li a3, STACK_SIZE
    li a4, (0b10 | (1<<3) | (1<<4))

    ecall

    bne zero, a0, __do_fail_exit

    ld sp, __mmap_where
    li t0, STACK_SIZE
    add sp, sp, t0

    call __elk_crt__clear_bss
    bne a0, zero, __do_fail_exit

    call __elk_crt__map_zero_page
    bne a0, zero, __do_fail_exit
    
    call __elk_crt__init_stdstreams
    bne a0, zero, __do_fail_exit
    
    call __elk_crt__init_signal
    bne a0, zero, __do_fail_exit

    addi sp, sp, -16
    addi a0, sp, 0 // argc_ptr
    addi a1, sp, 8 // argv_ptr

    call __elk_crt__get_argv
    ld a0, 0(sp) // argc
    ld a1, 8(sp) // argv

    addi sp, sp, 16

    call main

    // Exit using the value returned from main
    li a7, 0
    ecall

    j .

__do_fail_exit:
    li a7, 0 // exitcode of mmap
    ecall

    j .

.global __elk_crt__signal_handler_entry
.type __elk_crt__signal_handler_entry,@function
__elk_crt__signal_handler_entry:
    // Just exit(-1)
    li a0, -1
    li a7, 0
    ecall

.data

__mmap_where:
.quad 0

