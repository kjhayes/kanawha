
#include <kanawha/sleep.h>
#include <kanawha/sys-wrappers.h>

int
usleep(useconds_t useconds)
{
    int res;
    useconds += 999;
    res = kanawha_sys_sleep(useconds / 1000, SLEEP_DURATION_MSEC);
    if(res)
    {
        // TODO set errno
        return -1;
    }
    return 0;
}
