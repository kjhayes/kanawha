
#include <kanawha/process.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/fs/path.h>
#include <kanawha/file.h>

int
syscall_pipe(
        struct process *process,
        unsigned long flags,
        fd_t __user *out)
{
    int res;

    struct fs_path *pipe;

    res = fs_path_create_anon_pipe(&pipe);
    if(res) {
        return res;
    }

    fd_t fd;
    res = file_table_open_path(
            process->file_table,
            process,
            pipe,
            FILE_PERM_READ|FILE_PERM_WRITE,
            0,
            &fd);
    if(res) {
        fs_path_put(pipe);
        return res;
    }

    res = process_write_usermem(process, out, &fd, sizeof(fd_t));
    if(res) {
        file_table_close(
                process->file_table,
                process,
                fd);
        fs_path_put(pipe);
        return res;
    }

    fs_path_put(pipe);
    return 0;
}


