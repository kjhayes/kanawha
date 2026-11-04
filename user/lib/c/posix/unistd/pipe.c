
#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/syscall.h>
#include <unistd.h>

int
pipe(int fd_out[2])
{
    fd_t pipe_fd;
    int res;

    res = kanawha_sys_pipe(0, 0, &pipe_fd);
    if(res)
    {
        errno = res;
        return -1;
    }

    fd_t read_end = pipe_fd;
    fd_t write_end = pipe_fd;

    write_end = dup(read_end);

    fd_out[0] = read_end;
    fd_out[1] = write_end;

    return 0;
}
