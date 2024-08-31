
#include <kanawha/syscall.h>
#include <kanawha/process.h>

#define __KANAWHA_SYSCALL_KEEP_XLIST
#include <kanawha/uapi/syscall.h>

void
strace_begin_syscall(
        struct process *process,
        syscall_id_t id)
{
#ifdef CONFIG_STRACE_LOG_SYSCALL_BEGIN
    printk("PID(%ld) syscall [%s]\n",
            (sl_t)process->id, syscall_id_string(id));
#endif
}

void
strace_end_syscall(
        struct process *process,
        syscall_id_t id)
{
#ifdef CONFIG_STRACE_LOG_SYSCALL_END
    printk("PID(%ld) end syscall [%s]\n",
            (sl_t)process->id, syscall_id_string(id));
#endif
}

int
syscall_unknown(
        struct process *process,
        syscall_id_t id)
{
    eprintk("process(%ld) Unknown syscall (%ld)\n",
            (sl_t)process->id,
            (sl_t)id);
    return 0;
}

const char *
syscall_id_string(
        syscall_id_t id)
{
    const char *str;
    switch(id) {
#define SYSCALL_ID_STR_CASE(__name, __id, __NAME, ...)\
        case __id:\
            str = #__name;\
            break;
        default:
            str = "Unknown";
            break;
SYSCALL_XLIST(SYSCALL_ID_STR_CASE)
#undef SYSCALL_ID_STR_CASE
    }
    return str;
}

