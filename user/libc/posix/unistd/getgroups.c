
#include <unistd.h>
#include <errno.h>

int getgroups(int gidsetsize, gid_t grouplist[])
{
    if(gidsetsize == 0) {
        return 0;
    }
    errno = -EUNIMPL;
    return -1;
}

