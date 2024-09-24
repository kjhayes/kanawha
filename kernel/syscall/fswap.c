
#include <kanawha/uapi/syscall.h>
#include <kanawha/file.h>
#include <kanawha/assert.h>
#include <kanawha/vmem.h>

int
syscall_fswap(
        struct process *process,
        fd_t fd0,
        fd_t fd1)
{
    int res;

    DEBUG_ASSERT(KERNEL_ADDR(process));
    DEBUG_ASSERT(KERNEL_ADDR(process->file_table));

    res = file_table_swap(
            process->file_table,
            fd0,
            fd1);
    if(res) {
        return res;
    }

    return 0;
}

