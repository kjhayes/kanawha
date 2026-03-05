
#include <errno.h>
#include <signal.h>

int
sigprocmask(int how, const sigset_t *set, sigset_t *oset)
{
    errno = -EUNIMPL;
    return -1;
}
