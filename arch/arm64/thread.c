
#include <kanawha/thread.h>

void
arch_thread_run_threadless(threadless_f *func, void *in)
{
    panic("arch_thread_run_threadless is unimplemented");
}

__noreturn void
arch_thread_run_thread(struct thread_state *to_run)
{
    panic("arch_thread_run_thread is unimplemented!");
}

int
arch_init_thread_state(struct thread_state *state)
{
    return -EUNIMPL;
}

int
arch_deinit_thread_state(struct thread_state *state)
{
    return -EUNIMPL;
}

int
arch_dump_thread(printk_f *printer, struct thread_state *state)
{
    (*printer)("arch_dump_thread is unimplemented!");
    return -EUNIMPL;
}
