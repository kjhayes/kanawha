
#include <kanawha/usermode.h>
#include <kanawha/thread.h>
#include <arch/x64/thread.h>
#include <kanawha/types.h>
#include <kanawha/assert.h>
#include <kanawha/attribute.h>

extern __noreturn void
__x64_enter_usermode(void __user *starting_address, void *arg);

__noreturn
void arch_enter_usermode(void __user *starting_address, void *arg)
{
    // We should never return, so we can reset our thread_stack
    struct thread_state *state = current_thread();

    DEBUG_ASSERT(state);

    // NOTE: This wasn't here but as I was writing the RISCV
    // "enter_usermode" I suspect it is necessary (come check back on this later)
    //     -KJH
    // disable_irqs();

    state->arch_state.stack.stack_pointer =
        (uintptr_t)(void*)state->arch_state.stack.stack_base;

    __x64_enter_usermode(starting_address, arg);
}

