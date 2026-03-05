
#include <errno.h>
#include <signal.h>
#include <stdint.h>

void (*signal(int sig, void (*func)(int)))(int)
{
    if(func == SIG_DFL)
    {
        errno = -EUNIMPL;
        return SIG_ERR;
    }
    else if(func == SIG_ERR)
    {
        errno = -EUNIMPL;
        return SIG_ERR;
    }
    else if(func == SIG_HOLD)
    {
        errno = -EUNIMPL;
        return SIG_ERR;
    }
    else if(func == SIG_IGN)
    {
        errno = -EUNIMPL;
        return SIG_ERR;
    }
    else
    {
        errno = -EUNIMPL;
        return SIG_ERR;
    }
}
