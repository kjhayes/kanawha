
#include <kanawha/syscall.h>
#include <kanawha/process.h>

int
syscall_unknown(
        struct process *process,
        syscall_id_t id)
{
    eprintk("process(%ld) Unknown syscall (%ld)\n",
            (sl_t)process->id,
            (sl_t)id);
    return 0;
}

