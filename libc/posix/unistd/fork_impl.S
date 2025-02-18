
#include <kanawha/spawn.h>

.type __elk_posix__fork_entry, @function
__elk_posix__fork_entry:
    movq %rdi, %rsp
    jmp __elk_posix__fork_entry

.global __elk_posix__do_fork
.type __elk_posix__do_fork, @function
__elk_posix__do_fork:
    pushq %rdi

    movq $__elk_posix__fork_entry, %rdi // func
    movq %rsp, %rsi // arg
    movq $(SPAWN_MMAP_CLONE|SPAWN_FILES_CLONE|SPAWN_ENV_CLONE), %rdx // flags
    movq %rax, %rcx // pid_out

    callq kanawha_sys_spawn

__elk_posix__fork_parent_exit:
    popq %rdi
    retq

__elk_posix__fork_child_exit:
    popq %rax

    // Assumes that pid_t is 32-bit
    movl $0, 0(%rax)

    retq

