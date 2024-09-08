
#include <kanawha/usermode.h>
#include <kanawha/thread.h>
#include <arch/x64/thread.h>
#include <kanawha/stdint.h>
#include <kanawha/assert.h>

extern __attribute__((noreturn)) void
__x64_enter_usermode(void __user *starting_address, void *arg);

__attribute__((noreturn))
void arch_enter_usermode(void __user *starting_address, void *arg)
{
    // We should never return, so we can reset our thread_stack
    struct thread_state *state = current_thread();

    DEBUG_ASSERT(state);

    state->arch_state.stack.rsp =
        (uintptr_t)(void*)state->arch_state.stack.stack_base;

    __x64_enter_usermode(starting_address, arg);
}

