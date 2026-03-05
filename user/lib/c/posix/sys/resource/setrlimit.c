
#include <errno.h>
#include <sys/resource.h>

int
setrlimit(int resource, const struct rlimit *rlp)
{
    if(rlp->rlim_cur != RLIM_INFINITY)
    {
        errno = -EINVAL;
        return -1;
    }

    if(rlp->rlim_max != RLIM_INFINITY)
    {
        errno = -EINVAL;
        return -1;
    }

    return 0;
}
