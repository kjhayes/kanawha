
#include <arch/riscv64/asm/regs.S>
#include <arch/riscv64/csr.h>
#include <arch/riscv64/trap.h>
#include <kanawha/init.h>
#include <kanawha/irq.h>
#include <kanawha/irq_domain.h>
#include <kanawha/syscall.h>

static int
riscv64_syscall_handler(struct excp_state *excp_state,
                        struct irq_action *action)
{
    int res;

    struct riscv64_excp_state *state = (struct riscv64_excp_state *)excp_state;

    struct syscall_args args;
    args.args[0] = state->caller_regs[RISCV64_PUSHED_CALLER_REGS_INDEX_A0];
    args.args[1] = state->caller_regs[RISCV64_PUSHED_CALLER_REGS_INDEX_A1];
    args.args[2] = state->caller_regs[RISCV64_PUSHED_CALLER_REGS_INDEX_A2];
    args.args[3] = state->caller_regs[RISCV64_PUSHED_CALLER_REGS_INDEX_A3];
    args.args[4] = state->caller_regs[RISCV64_PUSHED_CALLER_REGS_INDEX_A4];
    args.args[5] = state->caller_regs[RISCV64_PUSHED_CALLER_REGS_INDEX_A5];

    struct process *process = current_process();

    process->user_ip =
        (void __user *)state->sepc +
        4; // We need the address of the instruction AFTER the ecall

    enable_irqs();
    res = handle_syscall(
        state->caller_regs[RISCV64_PUSHED_CALLER_REGS_INDEX_A7],
        &args,
        &state->caller_regs[RISCV64_PUSHED_CALLER_REGS_INDEX_A0]);
    if(res)
    {
        return IRQ_UNHANDLED;
    }
    disable_irqs();

    // reset the kernel stack
    process->thread.arch_state.stack.stack_pointer =
        process->thread.arch_state.stack.stack_base;

    // set our return address in userspace (may have been modified)
    state->sepc = (uint64_t)process->user_ip;

    return IRQ_NONE;
}

static int
riscv64_setup_syscalls(void)
{
    int res;

    struct irq_desc *desc = riscv64_exception_irq_desc(8);
    if(desc == NULL)
    {
        return -EDEFER;
    }

    struct irq_action *action =
        irq_install_handler(desc, NULL, riscv64_syscall_handler);
    if(action == NULL)
    {
        return -EDEFER;
    }

    return 0;
}
declare_init_desc(late, riscv64_setup_syscalls, "Installing syscall Handler");
