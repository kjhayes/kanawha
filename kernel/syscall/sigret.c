
#include <kanawha/uapi/signal.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/proc/signal.h>
#include <kanawha/proc/process.h>

int
syscall_sigret(
        struct process *process)
{
    int res;

    res = signal_complete(process);
    if(res) {
        return res;
    }

    return 0;
}

