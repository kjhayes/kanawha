
#include <errno.h>
#include <signal.h>

int
sigsuspend(const sigset_t *)
{
    errno = -EUNIMPL;
    return -1;
}
