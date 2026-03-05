
#include <errno.h>
#include <glob.h>

int
glob(const char *restrict pattern,
     int flags,
     int (*errfunc)(const char *epath, int eerrno),
     glob_t *restrict pglob)
{
    errno = -EUNIMPL;
    return -1;
}
