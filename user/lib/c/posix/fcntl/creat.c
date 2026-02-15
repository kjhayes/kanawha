
#include <fcntl.h>

int  creat(const char *name, mode_t mode)
{
    return open(name, O_WRONLY|O_CREAT|O_TRUNC, mode);
}

