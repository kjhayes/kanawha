
#include <sys/statfs.h>
#include <kanawha/sys-wrappers.h>
#include <kanawha/file.h>
#include <string.h>
#include <stdio.h>

int fstatfs(int fd, struct statfs *buf)
{
    memset(buf, 0, sizeof(*buf));

    return 0;
}

