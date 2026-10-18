
#include <errno.h>
#include <kanawha/environ.h>
#include <kanawha/syscall.h>
#include <stdlib.h>
#include <string.h>

int
unsetenv(const char *name)
{
    int res;

    res = kanawha_sys_environ(name, NULL, 0, ENV_CLEAR);
    if(res)
    {
        errno = res;
        return -1;
    }

    return 0;
}
