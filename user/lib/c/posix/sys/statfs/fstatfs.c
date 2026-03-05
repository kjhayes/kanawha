
#include <kanawha/file.h>
#include <kanawha/sys-wrappers.h>
#include <stdio.h>
#include <string.h>
#include <sys/statfs.h>

int
fstatfs(int fd, struct statfs *buf)
{
    memset(buf, 0, sizeof(*buf));

    return 0;
}
