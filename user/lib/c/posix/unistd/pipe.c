
#include <errno.h>
#include <kanawha/file.h>
#include <kanawha/syscall.h>
#include <unistd.h>

int
pipe(int fd_out[2])
{
    fd_t read_end;
    fd_t write_end;

    int res;

    res = kanawha_sys_pipe(0, 0, &read_end, &write_end);
    if(res)
    {
        errno = res;
        return -1;
    }

    fd_out[0] = read_end;
    fd_out[1] = write_end;
    return 0;
}
