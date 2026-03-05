
#include <arch/x64/exception.h>
#include <kanawha/excp.h>
#include <kanawha/init.h>
#include <kanawha/proc/process.h>
#include <kanawha/proc/signal.h>

static struct irq_action *x64_gpf_action = NULL;
static struct irq_action *x64_div_zero_action = NULL;
static struct irq_action *x64_inval_inst_action = NULL;

static int
x64_gp_fault_handler(struct excp_state *gen_excp_state,
                     struct irq_action *action)
{
    int res;

    struct x64_excp_state *excp_state = (struct x64_excp_state *)gen_excp_state;

    int ring_from = excp_state->cs & 0b11;
    if(ring_from == 0)
    {
        return IRQ_UNHANDLED;
    }

    struct process *process = current_process();
    if(process == NULL)
    {
        return IRQ_UNHANDLED;
    }

    res = signal_deliver(process, SIGNAL_ID_PROTFAULT, 0);
    if(res)
    {
        eprintk("Failed to deliver PROTFAULT signal to process on general "
                "protection fault (user_ip=%p) (err=%s)!\n",
                process->user_ip,
                errnostr(res));
        res = process_terminate(-EFAULT);
        if(res)
        {
            eprintk("Failed to terminate process which could not be "
                    "delivered "
                    "PROTFAULT (err=%s)\n",
                    errnostr(res));
            return res;
        }
        thread_abandon(force_resched());
    }

    return IRQ_HANDLED;
}

static int
x64_install_gp_fault_handler(void)
{
    // Defer as long as the vector domain is still NULL
    if(x64_vector_irq_domain == NULL)
    {
        return -EDEFER;
    }

    x64_gpf_action = irq_install_handler(x64_vector_irq_desc(13),
                                         NULL, // priv_state
                                         x64_gp_fault_handler);

    if(x64_gpf_action == NULL)
    {
        return -EINVAL;
    }
    return 0;
}
declare_init_desc(dynamic,
                  x64_install_gp_fault_handler,
                  "Installing x64 General Protection Fault Handler");

static int
x64_div_zero_fault_handler(struct excp_state *gen_excp_state,
                           struct irq_action *action)
{
    int res;

    struct x64_excp_state *excp_state = (struct x64_excp_state *)gen_excp_state;

    int ring_from = excp_state->cs & 0b11;
    if(ring_from == 0)
    {
        return IRQ_UNHANDLED;
    }

    struct process *process = current_process();
    if(process == NULL)
    {
        return IRQ_UNHANDLED;
    }

    res = signal_deliver(process, SIGNAL_ID_PROTFAULT, 0);
    if(res)
    {
        eprintk("Failed to deliver PROTFAULT signal to process on divide by "
                "zero fault (user_ip=%p) (err=%s)!\n",
                process->user_ip,
                errnostr(res));
        res = process_terminate(-EFAULT);
        if(res)
        {
            eprintk("Failed to terminate process which could not be "
                    "delivered "
                    "PROTFAULT (err=%s)\n",
                    errnostr(res));
            return res;
        }
        thread_abandon(force_resched());
    }

    return IRQ_HANDLED;
}

static struct irq_action *x64_gpf_action;

static int
x64_install_div_zero_fault_handler(void)
{
    // Defer as long as the vector domain is still NULL
    if(x64_vector_irq_domain == NULL)
    {
        return -EDEFER;
    }

    x64_div_zero_action = irq_install_handler(x64_vector_irq_desc(0),
                                              NULL, // priv_state
                                              x64_div_zero_fault_handler);

    if(x64_div_zero_action == NULL)
    {
        return -EINVAL;
    }
    return 0;
}
declare_init_desc(dynamic,
                  x64_install_div_zero_fault_handler,
                  "Installing x64 Divide By Zero Fault Handler");

static int
x64_inval_inst_fault_handler(struct excp_state *gen_excp_state,
                             struct irq_action *action)
{
    int res;

    struct x64_excp_state *excp_state = (struct x64_excp_state *)gen_excp_state;

    int ring_from = excp_state->cs & 0b11;
    if(ring_from == 0)
    {
        return IRQ_UNHANDLED;
    }

    struct process *process = current_process();
    if(process == NULL)
    {
        return IRQ_UNHANDLED;
    }

    res = signal_deliver(process, SIGNAL_ID_DECODEFAULT, 0);
    if(res)
    {
        eprintk("Failed to deliver DECODEFAULT signal to process on invalid "
                "instruction fault (user_ip=%p) (err=%s)!\n",
                process->user_ip,
                errnostr(res));
        res = process_terminate(-EFAULT);
        if(res)
        {
            eprintk("Failed to terminate process which could not be "
                    "delivered "
                    "DECODEFAULT (err=%s)\n",
                    errnostr(res));
            return res;
        }
        thread_abandon(force_resched());
    }

    return IRQ_HANDLED;
}

static int
x64_install_inval_inst_fault_handler(void)
{
    // Defer as long as the vector domain is still NULL
    if(x64_vector_irq_domain == NULL)
    {
        return -EDEFER;
    }

    x64_inval_inst_action = irq_install_handler(x64_vector_irq_desc(6),
                                                NULL, // priv_state
                                                x64_inval_inst_fault_handler);

    if(x64_inval_inst_action == NULL)
    {
        return -EINVAL;
    }
    return 0;
}
declare_init_desc(dynamic,
                  x64_install_inval_inst_fault_handler,
                  "Installing x64 Invalid Instruction Fault Handler");
