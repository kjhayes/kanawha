
#include <unistd.h>
#include <kanawha/sys-wrappers.h>

char *
getcwd(
    char *buffer,
    size_t buflen)
{
    int res;
    res = kanawha_sys_getcwd(buffer, buflen);
    if(res) {
        // TODO set errno
        return NULL;
    }
    return buffer;
}

