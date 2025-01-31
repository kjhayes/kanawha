
#include <kanawha/uapi/signal.h>
#include <kanawha/uapi/syscall.h>
#include <kanawha/proc/signal.h>
#include <kanawha/proc/process.h>

int
syscall_sigroute(
        struct process *process,
        void __user *entry)
{
    int res;

    res = signal_set_entry(process, entry);
    if(res) {
        return res;
    }

    return 0;
}

