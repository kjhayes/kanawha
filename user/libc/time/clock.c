
#include <time.h>
#include <kanawha/time.h>
#include <kanawha/sys-wrappers.h>

clock_t clock(void)
{
    ssize_t time = kanawha_sys_time(TIME_PROC|TIME_DURATION_MSEC);

    return (time * CLOCKS_PER_SEC) / 1000;
}

