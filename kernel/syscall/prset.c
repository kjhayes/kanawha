
#include <kanawha/syscall.h>
#include <kanawha/uapi/prinfo.h>

__attribute__((weak)) int
arch_prset(long field, unsigned long value)
{
    return -EINVAL;
}

int
syscall_prset(unsigned long type, long field, unsigned long value)
{
    int res;

    struct process *process = current_process();

    switch(type)
    {
    case PRINFO_TYPE_ARCH:
        return arch_prset(field, value);
    default:
        return -EINVAL;
    }
}
