
#define STACK_SIZE 0x200000

.global _start
_start:

    // Map the stack
    mov x0, 0
    mov x1, 0
    adr x2, __mmap_where
    mov x3, STACK_SIZE
    mov x4, (0b10 | (1<<3) | (1<<4) | (1<<5))
    mov x8, 7
    svc 0
    cbnz x0, __do_fail_exit

    ldr x0, __mmap_where
    mov sp, x0
    mov x0, STACK_SIZE
    add sp, sp, x0

    bl __elk_crt__clear_bss
    cbnz x0, __do_fail_exit
    bl __elk_crt__map_zero_page
    cbnz x0, __do_fail_exit
    bl __elk_crt__init_stdstreams
    cbnz x0, __do_fail_exit
    bl __elk_crt__init_signal
    cbnz x0, __do_fail_exit
    bl __elk_crt__populate_environ
    cbnz x0, __do_fail_exit

    sub sp, sp, 16
    mov x0, sp    // argc ptr
    add x1, sp, 8 // argv ptr
    
    bl __elk_crt__get_argv
    ldr x0, [sp, 0] // argc
    ldr x1, [sp, 8] // argv

    add sp, sp, 16

    bl main

__ret_from_main_exit:
    mov x8, 0
    svc 0
    b .

__do_fail_exit:
    mov x8, 0
    svc 0
    b .

.global __elk_crt__signal_handler_entry
.type __elk_crt__signal_handler_entry,@function
__elk_crt__signal_handler_entry:
    // Just exit(-1)
    mov x0, -1
    mov x8, 0
    svc 0

.data
__mmap_where:
.quad 0

