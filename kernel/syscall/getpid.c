
#include <kanawha/process.h>
#include <kanawha/assert.h>

pid_t
syscall_getpid(
        struct process *process)
{
    DEBUG_ASSERT(KERNEL_ADDR(process));
    return process->id;
}

