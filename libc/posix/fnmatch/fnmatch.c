
#include <fnmatch.h>
#include <errno.h>
#include <string.h>

int fnmatch(
        const char *pattern,
        const char *string,
        int flags)
{
    errno = -EUNIMPL;
    return -1;
}
