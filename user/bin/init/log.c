
#include <kanawha/dir.h>
#include <kanawha/errno.h>
#include <kanawha/file.h>
#include <kanawha/mount.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dir.h"
#include "log.h"

static void
all_term_puts_callback(int dir_fd, const char *file_name, void *_msg)
{
    int res;
    int fd = dir_fd;
    res = kanawha_sys_open(file_name,
                           FILE_PERM_WRITE,
                           FILE_MODE_OPEN_RELATIVE,
                           &fd);
    if(res)
    {
        return;
    }
    char *msg = _msg;
    size_t len = strlen(msg);
    ssize_t total_written = 0;
    while(total_written < len)
    {
        ssize_t cur_written;
        cur_written =
            kanawha_sys_write(fd, msg + total_written, len - total_written);
        if(cur_written <= 0)
        {
            break;
        }
        total_written += cur_written;
    }
    kanawha_sys_close(fd);
    return;
}

int
all_term_puts(char *msg)
{
    int res = 0;
    // res = for_each_file_under("/dev/term/", all_term_puts_callback, msg);
    return res;
}

char log_buffer[LOG_BUFLEN];
int printf_enabled = 0;
