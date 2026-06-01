
#include <kanawha/spawn.h>

.type __elk_posix__fork_child_entry, @function
__elk_posix__fork_child_entry:
    mv sp, a0
    j __elk_posix__fork_child_exit

.global __elk_posix__do_fork
.type __elk_posix__do_fork, @function
__elk_posix__do_fork:

    addi sp, sp, -(14 * 8)
    sd s0,   0(sp)
    sd s1,   8(sp)
    sd s2,  16(sp)
    sd s3,  24(sp)
    sd s4,  32(sp)
    sd s5,  40(sp)
    sd s6,  48(sp)
    sd s7,  56(sp)
    sd s8,  64(sp)
    sd s9,  72(sp)
    sd s10, 80(sp)
    sd s11, 88(sp)
    sd ra,  96(sp)

    mv a3, a0 // pid_out
    sd a3, 104(sp)

    la a0, __elk_posix__fork_child_entry // func
    mv a1, sp // arg
    li a2, (SPAWN_MMAP_CLONE|SPAWN_FILES_CLONE|SPAWN_ENV_CLONE) // flags

    call kanawha_sys_spawn

    // This should set x0 for us

__elk_posix__fork_parent_exit:
    ld s0,   0(sp)
    ld s1,   8(sp)
    ld s2,  16(sp)
    ld s3,  24(sp)
    ld s4,  32(sp)
    ld s5,  40(sp)
    ld s6,  48(sp)
    ld s7,  56(sp)
    ld s8,  64(sp)
    ld s9,  72(sp)
    ld s10, 80(sp)
    ld s11, 88(sp)
    ld ra,  96(sp)
    addi sp, sp, (14 * 8)

    ret

__elk_posix__fork_child_exit:

    ld s0,   0(sp)
    ld s1,   8(sp)
    ld s2,  16(sp)
    ld s3,  24(sp)
    ld s4,  32(sp)
    ld s5,  40(sp)
    ld s6,  48(sp)
    ld s7,  56(sp)
    ld s8,  64(sp)
    ld s9,  72(sp)
    ld s10, 80(sp)
    ld s11, 88(sp)
    ld ra,  96(sp)
    ld a0, 104(sp)
    addi sp, sp, (14 * 8)

    // Assumes that pid_t is 32-bit
    sd zero, 0(a0)

    // success
    mv a0, zero

    ret

