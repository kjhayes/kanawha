
#include <kanawha/syscall.h>
#include <kanawha/process.h>
#include <kanawha/file.h>

#define SYSCALL_OPEN_MAX_PATHLEN 256

int
syscall_close(
        struct process *process,
        fd_t file)
{
    int res;

    res = file_table_close_file(
            &process->file_table,
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

