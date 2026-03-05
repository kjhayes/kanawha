
#include <errno.h>
#include <unistd.h>

pid_t
tcgetpgrp(int filedes)
{
    errno = -EUNIMPL;
    return -1;
}
