
#include <errno.h>
#include <sgtty.h>

int
gtty(int filedes, struct sgttyb *attributes)
{
    return -ENOSYS;
}
int
stty(int filedes, struct sgttyb *attributes)
{
    return -ENOSYS;
}
