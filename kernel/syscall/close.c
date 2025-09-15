
#include <kanawha/syscall.h>
#include <kanawha/proc/process.h>
#include <kanawha/proc/file_table.h>

#define SYSCALL_OPEN_MAX_PATHLEN 256

int
syscall_close(
        fd_t file)
{
    int res;

    struct process *process = current_process();

    res = file_table_close(
            process->file_table,
            process,
            file);

    if(res) {
        eprintk("PID(%ld) syscall_close: file_table_close_file(%ld) returned %s\n",
                (sl_t)process->id, (sl_t)file, errnostr(res));
        return res;
    }

    dprintk("PID(%ld) syscall_close: fd=%ld\n",
            (sl_t)process->id, (sl_t)file);
    return 0;
}

