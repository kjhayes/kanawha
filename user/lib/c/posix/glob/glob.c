
#include <glob.h>
#include <errno.h>

int glob(
    const char *restrict pattern,
    int flags,
    int(*errfunc)(const char *epath, int eerrno),
    glob_t *restrict pglob)
{
    errno = -EUNIMPL;
    return -1;
}

