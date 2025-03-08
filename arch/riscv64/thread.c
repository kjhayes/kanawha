
#include <kanawha/thread.h>
#include <arch/riscv64/asm/regs.S>
#include <arch/riscv64/csr.h>

#define KERNEL_THREAD_STACK_ORDER 16

extern void __riscv64_thread_entry(void);

// Assembly Routines
extern void *
__riscv64_thread_run_threadless(void *in, threadless_f *func, uint64_t *sp_ptr);
extern __attribute__((noreturn)) void
__riscv64_thread_run_thread(void *rsp);

void 
arch_thread_run_threadless(
        threadless_f *func,
        void *in)
{
    __riscv64_thread_run_threadless(
            in, func,
            &current_thread()->arch_state.stack.stack_pointer);
}

__attribute__((noreturn)) void
arch_thread_run_thread(struct thread_state *to_run)
{
    __riscv64_thread_run_thread((void*)to_run->arch_state.stack.stack_pointer);
}

int arch_init_thread_state(struct thread_state *state)
{
    int res;
    struct arch_thread_state *arch = &state->arch_state;
    struct thread_stack *stack = &arch->stack;

    res = thread_stack_init(
            stack,
            KERNEL_THREAD_STACK_ORDER);
    if(res) {
        return res;
    }

    void *regs = thread_stack_alloca(stack,
            RISCV64_THREAD_CALLEE_PUSH_SIZE
           +RISCV64_THREAD_CALLER_PUSH_SIZE);

    uint64_t *callee_regs = regs;
    uint64_t *caller_regs = regs + RISCV64_THREAD_CALLEE_PUSH_SIZE;

    caller_regs[RISCV64_PUSHED_CALLER_REGS_INDEX_A0] = (uint64_t)state->in;
    caller_regs[RISCV64_PUSHED_CALLER_REGS_INDEX_A1] = (uint64_t)state->func;

    uint64_t sstatus = 0x0;
    sstatus |= SSTATUS_MASK_SPP;

    thread_stack_push(stack, (uint64_t)__riscv64_thread_entry);
    thread_stack_push(stack, sstatus); 

    return 0;
}

int arch_deinit_thread_state(struct thread_state *thread)
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
    return -EUNIMPL;
}


