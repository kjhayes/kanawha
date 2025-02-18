
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>

int
close(int fd) {
    kanawha_sys_close((fd_t)fd);
}

