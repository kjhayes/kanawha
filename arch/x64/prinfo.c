
#include <arch/x64/msr.h>
#include <kanawha/errno.h>
#include <kanawha/thread.h>
#include <kanawha/uapi/arch/x64/prinfo.h>

int
arch_prget(long field, unsigned long *value)
{
    switch(field)
    {
    case PRGET_X64_FSBASE:
        *value = read_msr(X64_MSR_FSBASE);
        return 0;
    default:
        return -EINVAL;
    }
}

int
arch_prset(long field, unsigned long value)
{
    switch(field)
    {
    case PRSET_X64_FSBASE:
        current_thread()->arch_state.fsbase = value;
        write_msr(X64_MSR_FSBASE, value);
        return 0;
    default:
        return -EINVAL;
    }
}
