
#include <kanawha/spawn.h>

.type __elk_posix__fork_child_entry, @function
__elk_posix__fork_child_entry:
    movq %rdi, %rsp
    jmp __elk_posix__fork_child_exit

.global __elk_posix__do_fork
.type __elk_posix__do_fork, @function
__elk_posix__do_fork:

    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq %rdi, %rcx // pid_out
    pushq %rdi

    movq $__elk_posix__fork_child_entry, %rdi // func
    movq %rsp, %rsi // arg
    movq $(SPAWN_MMAP_CLONE|SPAWN_FILES_CLONE|SPAWN_ENV_CLONE), %rdx // flags

    callq kanawha_sys_spawn
    // This should set %rax for us

__elk_posix__fork_parent_exit:
    popq %rdi

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx

    retq

__elk_posix__fork_child_exit:
    popq %rdi

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx

    // Assumes that pid_t is 32-bit
    movl $0, 0(%rdi)

    // success
    movq $0, %rax

    retq

