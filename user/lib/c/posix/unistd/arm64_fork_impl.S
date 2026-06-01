
#include <kanawha/spawn.h>

.type __elk_posix__fork_child_entry, @function
__elk_posix__fork_child_entry:
    mov sp, x0
    b __elk_posix__fork_child_exit

.global __elk_posix__do_fork
.type __elk_posix__do_fork, @function
__elk_posix__do_fork:

    sub sp, sp, 0x80
    stp x18, x19, [sp, 0x00]
    stp x20, x21, [sp, 0x10]
    stp x22, x23, [sp, 0x20]
    stp x24, x25, [sp, 0x30]
    stp x26, x27, [sp, 0x40]
    stp x28, x29, [sp, 0x50]
    stp x30, xzr, [sp, 0x60]

    mov x3, x0 // pid_out
    stp x3, xzr, [sp, 0x70]

    adr x0, __elk_posix__fork_child_entry // func
    mov x1, sp // arg
    mov x2, (SPAWN_MMAP_CLONE|SPAWN_FILES_CLONE|SPAWN_ENV_CLONE) // flags

    bl kanawha_sys_spawn

    // This should set x0 for us

__elk_posix__fork_parent_exit:
    ldp x18, x19, [sp, 0x00]
    ldp x20, x21, [sp, 0x10]
    ldp x22, x23, [sp, 0x20]
    ldp x24, x25, [sp, 0x30]
    ldp x26, x27, [sp, 0x40]
    ldp x28, x29, [sp, 0x50]
    ldp x30, xzr, [sp, 0x60]
    add sp, sp, 0x80 

    ret

__elk_posix__fork_child_exit:
    ldp x18, x19, [sp, 0x00]
    ldp x20, x21, [sp, 0x10]
    ldp x22, x23, [sp, 0x20]
    ldp x24, x25, [sp, 0x30]
    ldp x26, x27, [sp, 0x40]
    ldp x28, x29, [sp, 0x50]
    ldp x30, xzr, [sp, 0x60]
    ldp x0, xzr, [sp, 0x70]
    add sp, sp, 0x80

    // Assumes that pid_t is 32-bit
    mov w1, 0
    str w1, [x0]

    // success
    mov x0, 0

    ret
