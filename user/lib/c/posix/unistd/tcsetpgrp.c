
#include <errno.h>
#include <unistd.h>

int
tcsetpgrp(int filedes, pid_t pgid_id)
{
    errno = -EUNIMPL;
    return -1;
}
