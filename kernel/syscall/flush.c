
#include <kanawha/syscall.h>
#include <kanawha/fs/file.h>

int
syscall_flush(
        struct process *process,
        fd_t file,
        unsigned long flags) 
{
    int res;

    struct file *desc
        = file_table_get_file(
                process->file_table,
                process,
                file);
    if(desc == NULL) {
        return -ENXIO;
    }

    if((desc->access_flags & FILE_PERM_WRITE) == 0) {
        file_table_put_file(process->file_table, process, desc);
        return -EPERM;
    }

    res = direct_file_flush(desc, flags);
    if(res) {
        file_table_put_file(process->file_table, process, desc);
        return res;
    }

    file_table_put_file(process->file_table, process, desc);

    return 0;
}

