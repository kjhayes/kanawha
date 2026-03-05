
#include <errno.h>
#include <signal.h>

int
killpg(pid_t pgrp, int sig)
{
    if(sig <= 1)
    {
        errno = -EINVAL;
        return -1;
    }

    return kill(-pgrp, sig);
}
