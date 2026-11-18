
#include <kanawha/syscall.h>
#include <kanawha/time.h>
#include <time.h>

clock_t
clock(void)
{
    // This is wrong, we should be returning the CPU time,
    // not the real time.
    ssize_t time = kanawha_sys_time(TIME_PROC | TIME_DURATION_MSEC);

    return (clock_t)time;
}
