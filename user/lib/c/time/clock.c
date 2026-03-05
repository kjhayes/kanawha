
#include <kanawha/sys-wrappers.h>
#include <kanawha/time.h>
#include <time.h>

clock_t
clock(void)
{
    ssize_t time = kanawha_sys_time(TIME_PROC | TIME_DURATION_MSEC);

    return (time * CLOCKS_PER_SEC) / 1000;
}
