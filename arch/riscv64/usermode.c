
#include <kanawha/assert.h>
#include <kanawha/attribute.h>
#include <kanawha/irq.h>
#include <kanawha/printk.h>
#include <kanawha/thread.h>
#include <kanawha/usermode.h>

extern __noreturn void
__riscv64_enter_usermode(void __user *starting_address, void *arg);

__noreturn void
arch_enter_usermode(void __user *starting_address, void *arg)
{
    struct thread_state *state = current_thread();
    DEBUG_ASSERT(KERNEL_ADDR(state));

    disable_irqs();

    // Reset the thread stack
    state->arch_state.stack.stack_pointer =
        (uintptr_t)(void *)thread_stack_get_base(&state->arch_state.stack);

    __riscv64_enter_usermode(starting_address, arg);

    panic("Returned from __riscv64_enter_usermode!\n");
}
