
#include <unistd.h>
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>

int
pipe(int fd_out[2])
{
    fd_t read_end;
    fd_t write_end;

    int res;

    res = kanawha_sys_pipe(0, &read_end);
    if(res) {
        // TODO set errno
        return -1;
    }

    res = kanawha_sys_fmove(read_end, 0, FMOVE_DUP, &write_end);
    if(res) {
        // TODO set errno
        return -1;
    }

    fd_out[0] = read_end;
    fd_out[1] = write_end;
    return 0;
}

