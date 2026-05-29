
#include <kanawha/thread.h>
#include <arch/arm64/asm/regs.h>

#define KERNEL_THREAD_STACK_ORDER 21

extern void
__arm64_thread_entry(void *in, void(*func)(void *));
extern void
__arm64_thread_run_threadless(void *in, threadless_f *func, uint64_t *sp_ptr);
extern __noreturn void
__arm64_thread_run_thread(void *rsp);


void
arch_thread_run_threadless(threadless_f *func, void *in)
{
    __arm64_thread_run_threadless(
            in,
            func,
            &current_thread()->arch_state.stack.stack_pointer);
}

__noreturn void
arch_thread_run_thread(struct thread_state *to_run)
{
    __arm64_thread_run_thread(
            (void*)to_run->arch_state.stack.stack_pointer);
    panic("__arm64_thread_run_thread returned!\n");
}

int
arch_init_thread_state(struct thread_state *state)
{
    int res;
    struct arch_thread_state *arch = &state->arch_state;
    struct thread_stack *stack = &arch->stack;

    res = thread_stack_init(stack, KERNEL_THREAD_STACK_ORDER);
    if(res) {
        return res;
    }

    void *regs = thread_stack_alloca(stack,
            ARM64_THREAD_CALLEE_PUSH_SIZE
           +ARM64_THREAD_CALLER_PUSH_SIZE);

    uint64_t *callee_regs = regs;
    uint64_t *caller_regs = regs + ARM64_THREAD_CALLEE_PUSH_SIZE;

    caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X30] = (uint64_t)__arm64_thread_entry;
    caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X0] = (uint64_t)state->in;
    caller_regs[ARM64_PUSHED_CALLER_REG_INDEX_X1] = (uint64_t)state->func;

    return 0;
}

int
arch_deinit_thread_state(struct thread_state *thread)
{
    int res;

    res = thread_stack_deinit(&thread->arch_state.stack);
    if(res) {
        return res;
    }

    return 0;
}

int
arch_dump_thread(printk_f *printer, struct thread_state *state)
{
    (*printer)("arch_dump_thread is unimplemented!");
    return -EUNIMPL;
}
