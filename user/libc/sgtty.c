
#include <sgtty.h>
#include <errno.h>

int
gtty(int filedes, struct sgttyb *attributes)
{
    return -ENOSYS;
}
int
stty(int filedes, struct sgttyb * attributes)
{
    return -ENOSYS;
}

