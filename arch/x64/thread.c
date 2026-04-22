
#include <arch/x64/asm/regs.S>
#include <arch/x64/msr.h>
#include <kanawha/assert.h>
#include <kanawha/attribute.h>
#include <kanawha/errno.h>
#include <kanawha/kmalloc.h>
#include <kanawha/percpu.h>
#include <kanawha/printk.h>
#include <kanawha/stack.h>
#include <kanawha/string.h>
#include <kanawha/thread.h>

extern void
__x64_thread_entry(void);

extern void *
__x64_thread_run_threadless(void *in,
                            threadless_f *func,
                            uint64_t *rsp_ptr,
                            uint8_t *xsave_buffer);

extern __noreturn void
__x64_thread_run_thread(void *rsp, uint8_t *xsave_buffer);

void
arch_thread_run_threadless(threadless_f *func, void *in)
{
    struct thread_state *cur = current_thread();
    struct arch_thread_state *arch = &cur->arch_state;

    arch->fsbase = read_msr(X64_MSR_FSBASE);

    __x64_thread_run_threadless(in,
                                func,
                                &arch->stack.stack_pointer,
                                arch->xsave_buffer);
}

__noreturn void
arch_thread_run_thread(struct thread_state *to_run)
{
    dprintk("running thread %p with rsp=%p\n",
            to_run,
            to_run->arch_state.stack.stack_pointer);

    struct arch_thread_state *arch = &to_run->arch_state;

    write_msr(X64_MSR_FSBASE, arch->fsbase);

    __x64_thread_run_thread((void *)to_run->arch_state.stack.stack_pointer,
                            to_run->arch_state.xsave_buffer);
}

// 64kb Stacks
#define KERNEL_THREAD_STACK_ORDER 16

int
arch_init_thread_state(struct thread_state *state)
{
    int res;

    struct arch_thread_state *arch = &state->arch_state;
    struct thread_stack *stack = &state->arch_state.stack;

    res = thread_stack_init(stack, KERNEL_THREAD_STACK_ORDER);
    if(res)
    {
        return res;
    }

    dprintk("state->func = %p\n", state->func);
    dprintk("__x64_thread_entry = %p\n", __x64_thread_entry);

    thread_stack_push(stack, (uint64_t)state->func);
    thread_stack_push(stack, (uint64_t)__x64_thread_entry);

    uint64_t initial_rflags = 0x0;
    thread_stack_push(stack, (uint64_t)initial_rflags);

    void *regs =
        thread_stack_alloca(stack, (CALLEE_PUSH_SIZE + CALLER_PUSH_SIZE));
    memset(regs, 0, CALLEE_PUSH_SIZE + CALLER_PUSH_SIZE);

    uint64_t *callee_regs = regs;
    uint64_t *caller_regs = regs + CALLEE_PUSH_SIZE;

    caller_regs[1] = (uint64_t)state->in; // rdi

    memset(arch->xsave_buffer, 0, X64_XSAVE_BUFLEN);

    // arch_dump_thread(do_printk, state);

    return 0;
}

int
arch_deinit_thread_state(struct thread_state *state)
{
    int res;
    struct arch_thread_state *arch = &state->arch_state;
    res = thread_stack_deinit(&arch->stack);
    if(res)
    {
        return res;
    }
    return 0;
}

int
arch_dump_thread(printk_f *printer, struct thread_state *state)
{
    struct arch_thread_state *arch_state = &state->arch_state;
    return 0;
}

// This is just to avoid hard-coding any struct offsets into assembly
void *
__x64_get_current_thread_kernel_rsp(void)
{
    DEBUG_ASSERT_PERCPU_VALID();
    struct thread_state *thread = current_thread();
    return (void *)(uintptr_t)thread->arch_state.stack.stack_pointer;
}
