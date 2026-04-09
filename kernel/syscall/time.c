
#include <kanawha/syscall.h>
#include <kanawha/time.h>
#include <kanawha/uapi/time.h>

ssize_t
syscall_time(unsigned long flags)
{
    struct process *process = current_process();

    unsigned long type = (flags >> 0) & 0b11;
    unsigned long unit = (flags >> 2) & 0b11;

    duration_t value;
    switch(type)
    {
    case TIME_SYS:
        value = time_to_duration(current_timestamp());
        break;
    case TIME_PROC:
        value = duration_between(process->thread.creation_timestamp, current_timestamp());
        break;
    default:
        value = 0;
        break;
    }

    switch(unit)
    {
    case TIME_DURATION_MSEC:
        return duration_to_msec(value);
    case TIME_DURATION_SEC:
        return duration_to_sec(value);
    default:
        return 0;
    }
}
