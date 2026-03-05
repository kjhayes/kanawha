
#include <kanawha/sleep.h>
#include <kanawha/sys-wrappers.h>

unsigned int
sleep(unsigned int seconds)
{
    int res;
    res = kanawha_sys_sleep(seconds, SLEEP_DURATION_SEC);
    if(res)
    {
        return seconds;
    }
    return 0;
}
