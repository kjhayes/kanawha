
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

.global __elk_crt__default_signal_handler_entry
.type __elk_crt__default_signal_handler_entry,@function
__elk_crt__default_signal_handler_entry:
    addi sp, sp, -(15 * 8)
    sd a0,   0(sp) 
    sd a1,   8(sp)
    sd a2,  16(sp)
    sd a3,  24(sp)
    sd a4,  32(sp)
    sd a5,  40(sp)
    sd a6,  48(sp)
    sd a7,  56(sp)
    sd t0,  64(sp)
    sd t1,  72(sp)
    sd t2,  80(sp)
    sd t3,  88(sp)
    sd t4,  96(sp)
    sd t5, 104(sp)
    sd t6, 112(sp)

    call __elk_crt__default_signal_handler

    ld a0,   0(sp) 
    ld a1,   8(sp)
    ld a2,  16(sp)
    ld a3,  24(sp)
    ld a4,  32(sp)
    ld a5,  40(sp)
    ld a6,  48(sp)
    ld a7,  56(sp)
    ld t0,  64(sp)
    ld t1,  72(sp)
    ld t2,  80(sp)
    ld t3,  88(sp)
    ld t4,  96(sp)
    ld t5, 104(sp)
    ld t6, 112(sp)

    addi sp, sp, (15 * 8)

    li a7, 35 // SIGRET syscall
    ecall

.data

__mmap_where:
.quad 0

