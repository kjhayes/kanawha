
#include <signal.h>
#include <errno.h>

int sigprocmask(int how, const sigset_t *set, sigset_t *oset)
{
    errno = -EUNIMPL;
    return -1;
}

