
#include <sys/stat.h>

static mode_t __cmask = S_IRWXU | S_IRWXG | S_IRWXO;

mode_t umask(mode_t cmask)
{
    mode_t old = __cmask;
    __cmask = cmask;
    return old;
}

