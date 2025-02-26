
#include <kanawha/thread.h>

int arch_init_thread_state(struct thread_state *thread)
{
    return -EUNIMPL;
}

int arch_deinit_thread_state(struct thread_state *thread)
{
    return -EUNIMPL;
}

int arch_thread_switch(struct thread_state *to, struct thread_state *from)
{
    return -EUNIMPL;
}

void arch_thread_run_threadless(threadless_f *func, void *in)
{
    panic("arch_thread_run_threadless is unimplemented on riscv64!");
}

// Restore the state of "to_run" and begin executing it
// (Does not save state, so it should be run from a "threadless" context
__attribute__((noreturn))
void arch_thread_run_thread(struct thread_state *to_run)
{
    panic("arch_thread_run_threadless is unimplemented on riscv64!");
}

int
arch_dump_thread(printk_f *printer, struct thread_state *state)
{
    return -EUNIMPL;
}


