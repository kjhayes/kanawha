
#include <kanawha/sys-wrappers.h>
#include <kanawha/environ.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int unsetenv(const char *name)
{
    int res;

    res = kanawha_sys_environ(
            name,
            NULL,
            0,
            ENV_CLEAR);
    if(res) {
        errno = res;
        return -1;
    }

    return 0;
}

