
#include <kanawha/excp.h>
#include <kanawha/irq_domain.h>
#include <kanawha/proc/process.h>
#include <arch/arm64/excp.h>

struct irq_domain *arm64_excp_irq_domain = NULL;

void
arm64_handle_excp(
        struct arm64_excp_state *state)
{
    int res;

    if(arm64_excp_irq_domain == NULL) {
        panic("ARM64: Exception before setting up root IRQ domain!\n");
    }

    struct thread_state *cur_thread = current_thread();
    struct thread_state *new_thread;

    dprintk("arm64_handle_excp: hwirq=0x%lx, flags=0x%lx\n",
            (ul_t)state->hwirq,
            (ul_t)state->flags);
    if(state->flags & ARM64_EXCP_FLAG_USER) {
        struct process *process = current_process();
        DEBUG_ASSERT(KERNEL_ADDR(process));
        process->user_ip = (void __user *)state->elr;
    }

    irq_t irq = irq_domain_revmap(arm64_excp_irq_domain, state->hwirq);
    res = handle_irq(irq_to_desc(irq), (struct excp_state *)state);
    if(res == IRQ_UNHANDLED) {
        unhandled_interrupt((struct excp_state *)state);
    }

    soft_resched();
    if(current_thread_is_rescheduled()) {
        thread_switch();
    }

    if(state->flags & ARM64_EXCP_FLAG_USER) {
        struct process *process = current_process();
        DEBUG_ASSERT(KERNEL_ADDR(process));
        state->elr = (uintptr_t)process->user_ip;
    }

    return;
}


void
arch_excp_dump_state(struct excp_state *gen_state, printk_f *printer)
{
    struct arm64_excp_state *state = (void*)gen_state;
    (*printer)("--- CPU(%lu) %s%s%s ---\n",
            (ul_t)current_cpu_id(),
            state->flags & ARM64_EXCP_FLAG_32BIT ? "32-bit " : "",
            state->flags & ARM64_EXCP_FLAG_USER ? "Usermode " : "",
            state->hwirq == ARM64_EXCP_HWIRQ_SYNC ? "Synchronous Exception" :
            state->hwirq == ARM64_EXCP_HWIRQ_IRQ ? "Interrupt" :
            state->hwirq == ARM64_EXCP_HWIRQ_FIQ ? "Fast Interrupt" :
            state->hwirq == ARM64_EXCP_HWIRQ_SERROR ? "SError" :
            "Unknown Exception?");
    (*printer)("\tELR=%p\n", (void*)state->elr);
    (*printer)("\tESR=0x%lx\n", (uint64_t)state->esr);
    (*printer)("\tFAR=%p\n", (void*)state->far);
}

static int
arm64_alloc_exception_irq_domain(void)
{
    arm64_excp_irq_domain = alloc_irq_domain_linear(0, 4);
    if(arm64_excp_irq_domain == NULL)
    {
        return -ENOMEM;
    }

    printk("ARM64 Exception Domain Mapped to IRQ Range [%lu-%lu]\n",
           (unsigned long)irq_domain_revmap(arm64_excp_irq_domain, 0),
           (unsigned long)irq_domain_revmap(arm64_excp_irq_domain, 3));

    return 0;
}
declare_init_desc(dynamic,
                  arm64_alloc_exception_irq_domain,
                  "Creating ARM64 Exception IRQ Domain");

irq_t arm64_exception_irq(hwirq_t hwirq)
{
    if(arm64_excp_irq_domain == NULL) {
        return NULL_IRQ;
    }
    return irq_domain_revmap(arm64_excp_irq_domain, hwirq);
}

