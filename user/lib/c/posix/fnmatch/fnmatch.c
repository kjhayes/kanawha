
#include <errno.h>
#include <fnmatch.h>
#include <string.h>

int
fnmatch(const char *pattern, const char *string, int flags)
{
    errno = -EUNIMPL;
    return -1;
}
