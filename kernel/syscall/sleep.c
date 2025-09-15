
#include <kanawha/uapi/syscall.h>
#include <kanawha/uapi/sleep.h>
#include <kanawha/proc/process.h>
#include <kanawha/sleep.h>
#include <kanawha/errno.h>

int
syscall_sleep(
        size_t duration,
        unsigned long flags)
{
    struct process *process = current_process();

    switch(flags) {
        case SLEEP_DURATION_MSEC:
            thread_sleep(msec_to_duration(duration), 0);
            break;
        case SLEEP_DURATION_SEC:
            thread_sleep(sec_to_duration(duration), 0);
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

