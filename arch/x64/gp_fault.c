
#include <arch/x64/exception.h>
#include <kanawha/init.h>
#include <kanawha/process.h>
#include <kanawha/excp.h>

static int
x64_gp_fault_handler(
        struct excp_state *gen_excp_state,
        struct irq_action *action)
{
    int res;
    
    struct x64_excp_state *excp_state =
        (struct x64_excp_state*)gen_excp_state;

    int ring_from = excp_state->cs & 0b11;
    if(ring_from == 0) {
        return IRQ_UNHANDLED;
    }

    struct process *process = current_process();
    if(process == NULL) {
        return IRQ_UNHANDLED;
    }

    eprintk("Killing Process (%ld) for GP Fault! (RIP=%p) (error=%p)\n",
            (sl_t)process->id, excp_state->rip, (uintptr_t)excp_state->error_code);

    arch_excp_dump_state(gen_excp_state, printk);

    process_terminate(process, -1);

    return IRQ_HANDLED;
}

static struct irq_action *x64_gpf_action;

static int
x64_install_gp_fault_handler(void)
{
    // Defer as long as the vector domain is still NULL
    if(x64_vector_irq_domain == NULL) {
        return -EDEFER;
    }

    x64_gpf_action =
        irq_install_handler(
            x64_vector_irq_desc(13),
            NULL, // Device
            x64_gp_fault_handler);

    if(x64_gpf_action == NULL) {
        return -EINVAL;
    }
    return 0;
}
declare_init_desc(dynamic, x64_install_gp_fault_handler, "Installing x64 General Protection Fault Handler");

